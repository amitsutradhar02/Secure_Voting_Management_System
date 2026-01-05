from .auth_routes import auth_bp
from .user_routes import user_bp
from .election_routes import election_bp
from .vote_routes import vote_bp
from .post_routes import post_bp
from .support_routes import support_bp

__all__ = ['auth_bp', 'user_bp', 'election_bp', 'vote_bp', 'post_bp', 'support_bp']