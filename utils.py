import random
import string

def get_random_string(str_size=10):
    chars = string.ascii_letters + string.punctuation
    return ''.join(random.choice(chars) for x in range(str_size))

