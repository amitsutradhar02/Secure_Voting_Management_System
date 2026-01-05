from flask import Blueprint, render_template, request, redirect, url_for, flash, session
from middleware.rbac import require_auth, require_verified
from models.election import ElectionModel
from models.vote import VoteModel
from middleware.encryption_middleware import EncryptionMiddleware
from crypto.hmac import HMAC
from crypto.hashing import HashFunction
from config import Config

vote_bp = Blueprint('vote', __name__)
election_model = ElectionModel(Config.DATABASE_PATH)
vote_model = VoteModel(Config.DATABASE_PATH)
encryption_middleware = EncryptionMiddleware(Config.DATABASE_PATH)

@vote_bp.route('/cast/<election_id>', methods=['GET', 'POST'])
@require_auth
@require_verified
def cast_vote(election_id):
    """Cast vote page"""
    user_id = session.get('user_id')
    role = session.get('role')
    
    if role != 'voter':
        flash('Only voters can cast votes', 'error')
        return redirect(url_for('election.list_elections'))
    
    election = election_model.get_election(election_id)
    
    if not election:
        flash('Election not found', 'error')
        return redirect(url_for('election.list_elections'))
    
    if election['status'] != 'active':
        flash('This election is not currently active', 'error')
        return redirect(url_for('election.view_election', election_id=election_id))
    
    if vote_model.has_voted(election_id, user_id):
        flash('You have already voted in this election', 'warning')
        return redirect(url_for('vote.history'))
    
    candidates = election_model.get_candidates(election_id)
    
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
    
    if request.method == 'POST':
        candidate_id = request.form.get('candidate_id', '')
        
        if not candidate_id:
            flash('Please select a candidate', 'error')
            return render_template('vote/cast_vote.html', 
                                 election=election, 
                                 candidates=candidates)
        
        valid_candidate = False
        for candidate in candidates:
            if candidate['candidate_id'] == candidate_id:
                valid_candidate = True
                break
        
        if not valid_candidate:
            flash('Invalid candidate selection', 'error')
            return render_template('vote/cast_vote.html', 
                                 election=election, 
                                 candidates=candidates)

        voter_id_encrypted = encryption_middleware.encrypt_data(user_id, user_id)
        candidate_id_encrypted = encryption_middleware.encrypt_data(candidate_id, user_id)
        
        vote_data = f"{user_id}:{candidate_id}:{election_id}"
        vote_hash = HashFunction.hash_data(vote_data)
        
        hmac_key = session.get('session_token', 'default_key')
        vote_hmac = HMAC.generate_hmac(vote_data, hmac_key)
        
        ip_address = request.remote_addr
        
        success, message = vote_model.cast_vote(
            election_id=election_id,
            voter_id=user_id,
            candidate_id=candidate_id,
            voter_id_encrypted=voter_id_encrypted,
            candidate_id_encrypted=candidate_id_encrypted,
            vote_hash=vote_hash,
            vote_hmac=vote_hmac,
            ip_address=ip_address
        )
        
        if success:
            vote_model.mark_as_voted(election_id, user_id)
            
            flash('Vote cast successfully! Thank you for participating.', 'success')
            return redirect(url_for('vote.confirmation', election_id=election_id))
        else:
            flash(message, 'error')

    try:
        election['title'] = encryption_middleware.decrypt_data(
            election['title_encrypted'],
            election['created_by']
        )
    except:
        election['title'] = "Election"
    
    return render_template('vote/cast_vote.html', 
                         election=election, 
                         candidates=candidates)


@vote_bp.route('/confirmation/<election_id>')
@require_auth
def confirmation(election_id):
    user_id = session.get('user_id')
    
    election = election_model.get_election(election_id)
    
    if not election:
        flash('Election not found', 'error')
        return redirect(url_for('election.list_elections'))
    
    try:
        election['title'] = encryption_middleware.decrypt_data(
            election['title_encrypted'],
            election['created_by']
        )
    except:
        election['title'] = "Election"
    
    return render_template('vote/confirmation.html', election=election)

@vote_bp.route('/history')
@require_auth
def history():
    user_id = session.get('user_id')

    voting_history = vote_model.get_voting_history(user_id)
    
    for vote in voting_history:
        election = election_model.get_election(vote['election_id'])
        
        if election:
            try:
                vote['election_title'] = encryption_middleware.decrypt_data(
                    election['title_encrypted'],
                    election['created_by']
                )
            except:
                vote['election_title'] = "Election"
            
            vote['election_status'] = election['status']
        else:
            vote['election_title'] = "Unknown Election"
            vote['election_status'] = "unknown"
    
    return render_template('vote/history.html', voting_history=voting_history)