from flask import Blueprint, render_template, request, redirect, url_for, flash, session
from middleware.rbac import require_auth, admin_only
from models.support import SupportModel
from config import Config

support_bp = Blueprint('support', __name__)
support_model = SupportModel(Config.DATABASE_PATH)

@support_bp.route('/create', methods=['GET', 'POST'])
@require_auth
def create_ticket():

    user_id = session.get('user_id')
    username = session.get('username')
    role = session.get('role')
    
    if role == 'admin':
        flash('Admins cannot create support tickets', 'error')
        return redirect(url_for('user.dashboard'))
    
    if request.method == 'POST':
        subject = request.form.get('subject', '').strip()
        message = request.form.get('message', '').strip()
        priority = request.form.get('priority', 'medium')
        
        if not subject or not message:
            flash('Please fill all required fields', 'error')
            return render_template('support/create.html')
        
        success, ticket_id = support_model.create_ticket(
            user_id=user_id,
            username=username,
            subject=subject,
            message=message,
            priority=priority
        )
        
        if success:
            flash('Support ticket created successfully. We will respond soon!', 'success')
            return redirect(url_for('support.my_tickets'))
        else:
            flash('Failed to create support ticket', 'error')
    
    return render_template('support/create.html')

@support_bp.route('/my-tickets')
@require_auth
def my_tickets():

    user_id = session.get('user_id')
    role = session.get('role')
    
    if role == 'admin':
        return redirect(url_for('support.admin_tickets'))
    
    tickets = support_model.get_user_tickets(user_id)
    
    return render_template('support/my_tickets.html', tickets=tickets)


@support_bp.route('/admin/tickets')
@admin_only
def admin_tickets():

    status_filter = request.args.get('status', None)
    tickets = support_model.get_all_tickets(status=status_filter)
    
    return render_template('support/admin_tickets.html', tickets=tickets, status_filter=status_filter)


@support_bp.route('/admin/tickets/<ticket_id>/respond', methods=['GET', 'POST'])
@admin_only
def respond_ticket(ticket_id):

    ticket = support_model.get_ticket(ticket_id)
    
    if not ticket:
        flash('Ticket not found', 'error')
        return redirect(url_for('support.admin_tickets'))
    
    if request.method == 'POST':
        admin_response = request.form.get('response', '').strip()
        status = request.form.get('status', 'open')
        
        if not admin_response:
            flash('Please provide a response', 'error')
            return render_template('support/respond.html', ticket=ticket)
        
        success = support_model.respond_to_ticket(ticket_id, admin_response, status)
        
        if success:
            flash('Response sent successfully', 'success')
            return redirect(url_for('support.admin_tickets'))
        else:
            flash('Failed to send response', 'error')
    
    return render_template('support/respond.html', ticket=ticket)

