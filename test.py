import hashlib

def calculate_file_hash(file_path, hash_algorithm="sha256", block_size=65536):
    """
    Calculate the hash of a file using the specified hash algorithm.
    """
    hash_object = hashlib.new(hash_algorithm)

    with open(file_path, "rb") as file:
        for block in iter(lambda: file.read(block_size), b""):
            hash_object.update(block)

    return hash_object.hexdigest()

def is_file_malicious(file_path, known_hashes):
    """
    Check if a file is considered malicious based on a list of known malicious hashes.
    """
    file_hash = calculate_file_hash(file_path)

    print(file_hash)

    if file_hash in known_hashes:
        return True
    else:
        return False

def main():
    # Example usage:
    malicious_hashes = {
        "4d186321c1a7f0f354b297e8914ab240",
        "098f6bcd4621d373cade4e832627b4f6",
        "1a37ea9aea86c42094e339bfe1daa6c6408efb4f3149798c6180a1ea021490fb"
        # Add more malicious hashes as needed
    }

    file_to_check = "C:/Users/Amartya Jha/OS Project/file.txt"

    if is_file_malicious(file_to_check, malicious_hashes):
        print(f"The file {file_to_check} is malicious!")
    else:
        print(f"The file {file_to_check} is not malicious.")

main()