from flask import Blueprint, render_template, request, redirect, url_for, flash, session
from middleware.rbac import require_auth, admin_only
from models.post import PostModel
from middleware.encryption_middleware import EncryptionMiddleware
from utils.validators import sanitize_input
from config import Config

post_bp = Blueprint('post', __name__)
post_model = PostModel(Config.DATABASE_PATH)
encryption_middleware = EncryptionMiddleware(Config.DATABASE_PATH)


@post_bp.route('/')
@require_auth
def list_posts():
    user_id = session.get('user_id')
    role = session.get('role')
    
    # Get posts
    if role == 'admin':
        posts = post_model.get_all_posts(published_only=False)
    else:
        posts = post_model.get_all_posts(published_only=True)
    
    # Decrypt post data
    for post in posts:
        try:
            post['title'] = encryption_middleware.decrypt_data(
                post['title_encrypted'],
                post['author_id']
            ) or "Announcement"
        except:
            post['title'] = "Announcement"
    
    return render_template('posts/list.html', posts=posts, role=role)


@post_bp.route('/<post_id>')
@require_auth
def view_post(post_id):
    user_id = session.get('user_id')
    
    # Get post
    post = post_model.get_post(post_id)
    
    if not post:
        flash('Post not found', 'error')
        return redirect(url_for('post.list_posts'))
    
    # Decrypt post data
    try:
        post['title'] = encryption_middleware.decrypt_data(
            post['title_encrypted'],
            post['author_id']
        ) or "Announcement"
        
        post['content'] = encryption_middleware.decrypt_data(
            post['content_encrypted'],
            post['author_id']
        ) or "Content not available"
    except:
        post['title'] = "Announcement"
        post['content'] = "Content not available"
    
    return render_template('posts/view.html', post=post)


@post_bp.route('/create', methods=['GET', 'POST'])
@admin_only
def create_post():
    user_id = session.get('user_id')
    
    if request.method == 'POST':
        title = sanitize_input(request.form.get('title', '').strip())
        content = sanitize_input(request.form.get('content', '').strip())
        category = request.form.get('category', 'general')
        
        if not title or not content:
            flash('Title and content are required', 'error')
            return render_template('posts/create.html')
        
        # Encrypt data
        title_encrypted = encryption_middleware.encrypt_data(title, user_id)
        content_encrypted = encryption_middleware.encrypt_data(content, user_id)
        
        # Create post
        success, post_id = post_model.create_post(
            title=title,
            content=content,
            author_id=user_id,
            category=category,
            title_encrypted=title_encrypted,
            content_encrypted=content_encrypted
        )
        
        if success:
            flash('Post created successfully', 'success')
            return redirect(url_for('post.view_post', post_id=post_id))
        else:
            flash('Failed to create post', 'error')
    
    return render_template('posts/create.html')


@post_bp.route('/<post_id>/edit', methods=['GET', 'POST'])
@admin_only
def edit_post(post_id):
    user_id = session.get('user_id')
    
    # Get post
    post = post_model.get_post(post_id)
    
    if not post:
        flash('Post not found', 'error')
        return redirect(url_for('post.list_posts'))
    
    if request.method == 'POST':
        title = sanitize_input(request.form.get('title', '').strip())
        content = sanitize_input(request.form.get('content', '').strip())
        category = request.form.get('category', 'general')
        
        if not title or not content:
            flash('Title and content are required', 'error')
            return render_template('posts/edit.html', post=post)
        
        # Encrypt data
        title_encrypted = encryption_middleware.encrypt_data(title, user_id)
        content_encrypted = encryption_middleware.encrypt_data(content, user_id)
        
        # Update post
        success = post_model.update_post(
            post_id=post_id,
            title_encrypted=title_encrypted,
            content_encrypted=content_encrypted,
            category=category
        )
        
        if success:
            flash('Post updated successfully', 'success')
            return redirect(url_for('post.view_post', post_id=post_id))
        else:
            flash('Failed to update post', 'error')
    
    # Decrypt post data for editing
    try:
        post['title'] = encryption_middleware.decrypt_data(
            post['title_encrypted'],
            post['author_id']
        )
        post['content'] = encryption_middleware.decrypt_data(
            post['content_encrypted'],
            post['author_id']
        )
    except:
        flash('Failed to decrypt post data', 'error')
        return redirect(url_for('post.list_posts'))
    
    return render_template('posts/edit.html', post=post)


@post_bp.route('/<post_id>/delete', methods=['POST'])
@admin_only
def delete_post(post_id):
    success = post_model.delete_post(post_id)
    
    if success:
        flash('Post deleted successfully', 'success')
    else:
        flash('Failed to delete post', 'error')
    
    return redirect(url_for('post.list_posts'))


@post_bp.route('/<post_id>/publish', methods=['POST'])
@admin_only
def publish_post(post_id):
    success = post_model.publish_post(post_id)
    
    if success:
        flash('Post published successfully', 'success')
    else:
        flash('Failed to publish post', 'error')
    
    return redirect(url_for('post.view_post', post_id=post_id))


@post_bp.route('/<post_id>/unpublish', methods=['POST'])
@admin_only
def unpublish_post(post_id):
    success = post_model.unpublish_post(post_id)
    
    if success:
        flash('Post unpublished successfully', 'success')
    else:
        flash('Failed to unpublish post', 'error')
    
    return redirect(url_for('post.view_post', post_id=post_id))