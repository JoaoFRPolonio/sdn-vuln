import redis

# Connect to the Redis server
redis_host = 'localhost'  # Replace with your Redis server's host
redis_port = 6379
redis_client = redis.Redis(host=redis_host, port=redis_port, decode_responses=True)

# Set the key-value pair in Redis
key = 'host'
value = '192.168.13.9'
redis_client.set(key, value)

# Retrieve and print the value using the key
stored_value = redis_client.get(key)
print(f"{key}: {stored_value}")
