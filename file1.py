import random
import math
import datetime
import hashlib
import os

class ComplexDataProcessor:
    def __init__(self, data_size=100):
        self.data = self._generate_random_data(data_size)
        self.processed_data = {}

    def _generate_random_data(self, size):
        data = []
        for _ in range(size):
            data.append({
                'id': random.randint(1000, 9999),
                'value': random.uniform(-100, 100),
                'timestamp': datetime.datetime.now() - datetime.timedelta(days=random.randint(0, 365)),
                'metadata': {
                    'status': random.choice(['active', 'inactive', 'pending']),
                    'tags': [random.choice(['alpha', 'beta', 'gamma']) for _ in range(random.randint(1, 3))]
                }
            })
        return data

    def process_data(self):
        for item in self.data:
            item_id = item['id']
            value = item['value']
            timestamp = item['timestamp']
            status = item['metadata']['status']
            tags = item['metadata']['tags']

            hashed_id = hashlib.sha256(str(item_id).encode()).hexdigest()
            modified_value = math.sin(value) * math.cos(value)
            time_diff = (datetime.datetime.now() - timestamp).total_seconds()
            
            processed_item = {
                'hashed_id': hashed_id,
                'modified_value': modified_value,
                'time_diff': time_diff,
                'status': status,
                'tags': tags,
                'extra_data': self._generate_extra_data()
            }
            self.processed_data[item_id] = processed_item

    def _generate_extra_data(self):
        return {
            'random_number': random.gauss(0, 1),
            'random_string': os.urandom(16).hex(),
            'random_list': random.sample(range(1, 100), random.randint(5, 10))
        }

    def get_processed_data(self):
        return self.processed_data

    def filter_data(self, status_filter=None, tag_filter=None):
        filtered_data = {}
        for item_id, item in self.processed_data.items():
            if status_filter and item['status'] != status_filter:
                continue
            if tag_filter and not any(tag in item['tags'] for tag in tag_filter):
                continue
            filtered_data[item_id] = item
        return filtered_data

def main():
    processor = ComplexDataProcessor(data_size=50)
    processor.process_data()
    processed_data = processor.get_processed_data()
    print("Processed Data:", processed_data)

    filtered_data = processor.filter_data(status_filter='active', tag_filter=['alpha'])
    print("\nFiltered Data:", filtered_data)

if __name__ == "__main__":
    main()