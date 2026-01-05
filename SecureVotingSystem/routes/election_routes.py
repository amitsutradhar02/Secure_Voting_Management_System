from flask import Blueprint, render_template, request, redirect, url_for, flash, session
from middleware.rbac import require_auth, admin_only
from models.election import ElectionModel
from middleware.encryption_middleware import EncryptionMiddleware
from utils.validators import validate_date_format, validate_date_range, sanitize_input
from config import Config

election_bp = Blueprint('election', __name__)
election_model = ElectionModel(Config.DATABASE_PATH)
encryption_middleware = EncryptionMiddleware(Config.DATABASE_PATH)


@election_bp.route('/')
@require_auth
def list_elections():

    user_id = session.get('user_id')
    role = session.get('role')
    elections = election_model.get_all_elections()
    
    for election in elections:
        try:
            election['title'] = encryption_middleware.decrypt_data(
                election['title_encrypted'], 
                election['created_by']
            ) or "Election"
        except:
            election['title'] = "Election"
    
    return render_template('election/list.html', elections=elections, role=role)


@election_bp.route('/create', methods=['GET', 'POST'])
@admin_only
def create_election():

    user_id = session.get('user_id')
    
    if request.method == 'POST':
        title = sanitize_input(request.form.get('title', '').strip())
        description = sanitize_input(request.form.get('description', '').strip())
        start_date = request.form.get('start_date', '')
        end_date = request.form.get('end_date', '')
        
        # Validate
        if not title or not start_date or not end_date:
            flash('Please fill all required fields', 'error')
            return render_template('election/create.html')
        
        is_valid_start, msg_start = validate_date_format(start_date)
        if not is_valid_start:
            flash(msg_start, 'error')
            return render_template('election/create.html')
        
        is_valid_end, msg_end = validate_date_format(end_date)
        if not is_valid_end:
            flash(msg_end, 'error')
            return render_template('election/create.html')
        
        is_valid_range, msg_range = validate_date_range(start_date, end_date)
        if not is_valid_range:
            flash(msg_range, 'error')
            return render_template('election/create.html')
        
        # Encrypt data
        title_encrypted = encryption_middleware.encrypt_data(title, user_id)
        description_encrypted = encryption_middleware.encrypt_data(description, user_id) if description else None
        
        # Create election
        success, election_id = election_model.create_election(
            title=title,
            description=description,
            start_date=start_date,
            end_date=end_date,
            created_by=user_id,
            title_encrypted=title_encrypted,
            description_encrypted=description_encrypted
        )
        
        if success:
            flash('Election created successfully', 'success')
            return redirect(url_for('election.view_election', election_id=election_id))
        else:
            flash('Failed to create election', 'error')
    
    return render_template('election/create.html')


@election_bp.route('/<election_id>')
@require_auth
def view_election(election_id):

    user_id = session.get('user_id')
    
    # Get election
    election = election_model.get_election(election_id)
    
    if not election:
        flash('Election not found', 'error')
        return redirect(url_for('election.list_elections'))
    
    # Decrypt election data
    try:
        election['title'] = encryption_middleware.decrypt_data(
            election['title_encrypted'],
            election['created_by']
        ) or "Election"
        
        if election['description_encrypted']:
            election['description'] = encryption_middleware.decrypt_data(
                election['description_encrypted'],
                election['created_by']
            )
    except:
        election['title'] = "Election"
        election['description'] = ""
    
    # Get candidates
    candidates = election_model.get_candidates(election_id)
    
    # Decrypt candidate data
    for candidate in candidates:
        try:
            candidate['name'] = encryption_middleware.decrypt_data(
                candidate['name_encrypted'],
                election['created_by']
            ) or "Candidate"
            
            candidate['party'] = encryption_middleware.decrypt_data(
                candidate['party_encrypted'],
                election['created_by']
            ) or ""
        except:
            candidate['name'] = "Candidate"
            candidate['party'] = ""
    
    return render_template('election/view.html', 
                         election=election, 
                         candidates=candidates)


@election_bp.route('/<election_id>/add-candidate', methods=['GET', 'POST'])
@admin_only
def add_candidate(election_id):

    user_id = session.get('user_id')
    
    # Get election
    election = election_model.get_election(election_id)
    
    if not election:
        flash('Election not found', 'error')
        return redirect(url_for('election.list_elections'))
    
    if request.method == 'POST':
        name = sanitize_input(request.form.get('name', '').strip())
        party = sanitize_input(request.form.get('party', '').strip())
        description = sanitize_input(request.form.get('description', '').strip())
        symbol = sanitize_input(request.form.get('symbol', '').strip())
        
        if not name:
            flash('Candidate name is required', 'error')
            return render_template('election/add_candidate.html', election=election)
        
        # Encrypt data
        name_encrypted = encryption_middleware.encrypt_data(name, user_id)
        party_encrypted = encryption_middleware.encrypt_data(party, user_id) if party else None
        description_encrypted = encryption_middleware.encrypt_data(description, user_id) if description else None
        symbol_encrypted = encryption_middleware.encrypt_data(symbol, user_id) if symbol else None
        
        # Add candidate
        success, candidate_id = election_model.add_candidate(
            election_id=election_id,
            name=name,
            party=party,
            description=description,
            symbol=symbol,
            name_encrypted=name_encrypted,
            party_encrypted=party_encrypted,
            description_encrypted=description_encrypted,
            symbol_encrypted=symbol_encrypted
        )
        
        if success:
            flash('Candidate added successfully', 'success')
            return redirect(url_for('election.view_election', election_id=election_id))
        else:
            flash('Failed to add candidate', 'error')
    
    # Decrypt election title
    try:
        election['title'] = encryption_middleware.decrypt_data(
            election['title_encrypted'],
            election['created_by']
        )
    except:
        election['title'] = "Election"
    
    return render_template('election/add_candidate.html', election=election)


@election_bp.route('/<election_id>/live-results')
@admin_only
def live_results(election_id):

    user_id = session.get('user_id')
    
    # Get election
    election = election_model.get_election(election_id)
    
    if not election:
        flash('Election not found', 'error')
        return redirect(url_for('election.list_elections'))
    
    # Check if election is active
    if election['status'] != 'active':
        flash('Live results are only available for active elections', 'warning')
        return redirect(url_for('election.view_election', election_id=election_id))
    
    # Get live results
    from models.vote import VoteModel
    import sqlite3
    vote_model = VoteModel(Config.DATABASE_PATH)
    
    # Get all votes for this election to properly decrypt candidate IDs
    all_votes = vote_model.get_all_votes(election_id)
    
    # Get candidates
    candidates = election_model.get_candidates(election_id)
    
    # Create candidate lookup by ID
    candidate_lookup = {c['candidate_id']: c for c in candidates}
    
    # Get all voters who voted in this election
    conn = sqlite3.connect(Config.DATABASE_PATH)
    cursor = conn.cursor()
    cursor.execute('SELECT DISTINCT voter_id FROM vote_tracking WHERE election_id = ?', (election_id,))
    voter_ids = [row[0] for row in cursor.fetchall()]
    conn.close()
    
    vote_counts = {}
    for vote in all_votes:
        candidate_id = None
 
        if vote.get('candidate_id_encrypted'):

            for voter_id in voter_ids:
                decrypted = encryption_middleware.decrypt_data(
                    vote['candidate_id_encrypted'],
                    voter_id
                )
                if decrypted and decrypted in candidate_lookup:
                    candidate_id = decrypted
                    break

            if not candidate_id:
                decrypted = encryption_middleware.decrypt_data(
                    vote['candidate_id_encrypted'],
                    election['created_by']
                )
                if decrypted and decrypted in candidate_lookup:
                    candidate_id = decrypted
        
        if candidate_id:
            vote_counts[candidate_id] = vote_counts.get(candidate_id, 0) + 1
    
    results = []
    for candidate_id, vote_count in sorted(vote_counts.items(), key=lambda x: x[1], reverse=True):
        candidate = candidate_lookup.get(candidate_id)
        if candidate:
            candidate_name = encryption_middleware.decrypt_data(
                candidate['name_encrypted'],
                election['created_by']
            ) or "Candidate"
            party = encryption_middleware.decrypt_data(
                candidate['party_encrypted'],
                election['created_by']
            ) if candidate.get('party_encrypted') else ""
            
            results.append({
                'candidate_id_encrypted': candidate_id, 
                'vote_count': vote_count,
                'candidate_name': candidate_name,
                'party': party
            })
    

    election['title'] = encryption_middleware.decrypt_data(
        election['title_encrypted'],
        election['created_by']
    ) or "Election"
    
    return render_template('election/live_results.html', 
                         election=election, 
                         results=results)


@election_bp.route('/<election_id>/results')
@require_auth
def view_results(election_id):

    user_id = session.get('user_id')
    election = election_model.get_election(election_id)
    
    if not election:
        flash('Election not found', 'error')
        return redirect(url_for('election.list_elections'))

    if election['status'] != 'completed':
        flash('Results are only available after election ends', 'warning')
        return redirect(url_for('election.view_election', election_id=election_id))

    from models.vote import VoteModel
    import sqlite3
    vote_model = VoteModel(Config.DATABASE_PATH)

    all_votes = vote_model.get_all_votes(election_id)
    candidates = election_model.get_candidates(election_id)
    candidate_lookup = {c['candidate_id']: c for c in candidates}
    
    conn = sqlite3.connect(Config.DATABASE_PATH)
    cursor = conn.cursor()
    cursor.execute('SELECT DISTINCT voter_id FROM vote_tracking WHERE election_id = ?', (election_id,))
    voter_ids = [row[0] for row in cursor.fetchall()]
    conn.close()

    vote_counts = {}
    for vote in all_votes:
        candidate_id = None
        
        if vote.get('candidate_id_encrypted'):

            for voter_id in voter_ids:
                decrypted = encryption_middleware.decrypt_data(
                    vote['candidate_id_encrypted'],
                    voter_id
                )
                if decrypted and decrypted in candidate_lookup:
                    candidate_id = decrypted
                    break

            if not candidate_id:
                decrypted = encryption_middleware.decrypt_data(
                    vote['candidate_id_encrypted'],
                    election['created_by']
                )
                if decrypted and decrypted in candidate_lookup:
                    candidate_id = decrypted
        
        if candidate_id:
            vote_counts[candidate_id] = vote_counts.get(candidate_id, 0) + 1

    results = []
    for candidate_id, vote_count in sorted(vote_counts.items(), key=lambda x: x[1], reverse=True):
        candidate = candidate_lookup.get(candidate_id)
        if candidate:
            candidate_name = encryption_middleware.decrypt_data(
                candidate['name_encrypted'],
                election['created_by']
            ) or "Candidate"
            party = encryption_middleware.decrypt_data(
                candidate['party_encrypted'],
                election['created_by']
            ) if candidate.get('party_encrypted') else ""
            
            results.append({
                'candidate_id_encrypted': candidate_id,
                'vote_count': vote_count,
                'candidate_name': candidate_name,
                'party': party
            })
    
    # Decrypt election title
    election['title'] = encryption_middleware.decrypt_data(
        election['title_encrypted'],
        election['created_by']
    ) or "Election"
    
    return render_template('election/results.html', 
                         election=election, 
                         results=results)


@election_bp.route('/<election_id>/update-status', methods=['POST'])
@admin_only
def update_status(election_id):
    status = request.form.get('status', '')
    
    if status not in ['upcoming', 'active', 'completed', 'cancelled']:
        flash('Invalid status', 'error')
        return redirect(url_for('election.view_election', election_id=election_id))
    
    success = election_model.update_election_status(election_id, status)
    
    if success:
        flash(f'Election status updated to {status}', 'success')
    else:
        flash('Failed to update status', 'error')
    
    return redirect(url_for('election.view_election', election_id=election_id))


@election_bp.route('/<election_id>/delete', methods=['POST'])
@admin_only
def delete_election(election_id):
    success = election_model.delete_election(election_id)
    
    if success:
        flash('Election deleted successfully', 'success')
    else:
        flash('Failed to delete election', 'error')
    
    return redirect(url_for('election.list_elections'))