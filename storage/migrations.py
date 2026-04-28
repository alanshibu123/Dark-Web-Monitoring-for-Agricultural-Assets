"""
Database migration utilities for schema updates
"""

import os
import sys
import logging
from alembic.config import Config
from alembic import command
from alembic.migration import MigrationContext
from alembic.autogenerate import compare_metadata

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from storage.database import Base, DatabaseManager

logger = logging.getLogger(__name__)


class DatabaseMigrator:
    """Handles database migrations"""
    
    def __init__(self, db_manager: DatabaseManager):
        self.db_manager = db_manager
        self.alembic_cfg = None
        
    def setup_alembic(self, migration_dir: str = 'migrations'):
        """Setup Alembic for migrations"""
        if not os.path.exists(migration_dir):
            os.makedirs(migration_dir)
            
        alembic_cfg = Config()
        alembic_cfg.set_main_option('script_location', migration_dir)
        alembic_cfg.set_main_option('sqlalchemy.url', self.db_manager.connection_string)
        
        self.alembic_cfg = alembic_cfg
        
        # Initialize if not already done
        if not os.path.exists(os.path.join(migration_dir, 'env.py')):
            command.init(self.alembic_cfg, migration_dir)
            logger.info(f"Alembic initialized in {migration_dir}")
    
    def create_migration(self, message: str = 'auto_migration'):
        """Create a new migration"""
        if not self.alembic_cfg:
            self.setup_alembic()
        
        command.revision(self.alembic_cfg, autogenerate=True, message=message)
        logger.info(f"Created migration: {message}")
    
    def upgrade(self, revision: str = 'head'):
        """Upgrade to latest revision"""
        if not self.alembic_cfg:
            self.setup_alembic()
        
        command.upgrade(self.alembic_cfg, revision)
        logger.info(f"Upgraded database to {revision}")
    
    def downgrade(self, revision: str = '-1'):
        """Downgrade to previous revision"""
        if not self.alembic_cfg:
            self.setup_alembic()
        
        command.downgrade(self.alembic_cfg, revision)
        logger.info(f"Downgraded database to {revision}")


if __name__ == "__main__":
    # Quick test
    db = DatabaseManager('sqlite:///test.db')
    migrator = DatabaseMigrator(db)
    print("Migration utilities ready")