import sqlite3
from typing import List, Dict, Optional

DB_PATH = 'db/incident_events.db'

class EventStore:
    def __init__(self, db_path: str = DB_PATH):
        self.db_path = db_path
        self.conn = None
        self.cursor = None

    def connect(self):
        self.conn = sqlite3.connect(self.db_path)
        self.cursor = self.conn.cursor()
        self._create_table()

    def _create_table(self):
        self.cursor.execute('''
            CREATE TABLE IF NOT EXISTS events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                source TEXT NOT NULL,
                event_type TEXT NOT NULL,
                details TEXT
            )
        ''')
        self.conn.commit()

    def insert_event(self, event: Dict[str, str]):
        """
        Insert a single event into the database.
        event should have keys: timestamp, source, event_type, details (details can be optional)
        """
        self.cursor.execute('''
            INSERT INTO events (timestamp, source, event_type, details)
            VALUES (?, ?, ?, ?)
        ''', (
            event.get('timestamp'),
            event.get('source'),
            event.get('event_type'),
            event.get('details', None)
        ))
        self.conn.commit()

    def query_events(self, start_time: Optional[str] = None, end_time: Optional[str] = None) -> List[Dict]:
        """
        Query events optionally between start_time and end_time (ISO 8601 strings).
        Returns list of event dictionaries.
        """
        query = 'SELECT id, timestamp, source, event_type, details FROM events'
        params = []
        conditions = []

        if start_time:
            conditions.append('timestamp >= ?')
            params.append(start_time)
        if end_time:
            conditions.append('timestamp <= ?')
            params.append(end_time)

        if conditions:
            query += ' WHERE ' + ' AND '.join(conditions)

        query += ' ORDER BY timestamp ASC'

        self.cursor.execute(query, params)
        rows = self.cursor.fetchall()

        events = []
        for row in rows:
            events.append({
                'id': row[0],
                'timestamp': row[1],
                'source': row[2],
                'event_type': row[3],
                'details': row[4],
            })
        return events

    def close(self):
        if self.conn:
            self.conn.close()
            self.conn = None
            self.cursor = None

# Example usage
if __name__ == "__main__":
    store = EventStore()
    store.connect()

    # Insert example event
    store.insert_event({
        'timestamp': '2025-05-29T12:30:00Z',
        'source': 'syslog',
        'event_type': 'login_success',
        'details': 'User admin logged in successfully'
    })

    # Query events
    events = store.query_events(start_time='2025-05-29T00:00:00Z', end_time='2025-05-30T00:00:00Z')
    for e in events:
        print(e)

    store.close()

