import streamlit as st
import hashlib

#uploading files to be checked
st.title('Upload file here')

#uploaded_file = st.file_uploader("Upload Files",type=['png','jpeg','jpg'])
uploaded_file = st.file_uploader("Upload Files")

if uploaded_file is not None:
    file_details = {"FileName":uploaded_file.name,"FileType":uploaded_file.type,"FileSize":uploaded_file.size}
    st.write(file_details)

def calculate_file_hash(uploaded_file, hash_algorithm="sha256", block_size=65536):
    """
    Calculate the hash of a file using the specified hash algorithm.
    """
    hash_object = hashlib.new(hash_algorithm)

    with open(uploaded_file, "rb") as file:
        for block in iter(lambda: file.read(block_size), b""):
            hash_object.update(block)

    return hash_object.hexdigest()

def is_file_malicious(uploaded_files, known_hashes):
    """
    Check if a file is considered malicious based on a list of known malicious hashes.
    """
    file_hash = calculate_file_hash(uploaded_file)

    print(file_hash)

    if file_hash in known_hashes:
        flagg = 1
    else:
        flagg = 0

def main(flagg):
    # Example usage:
    malicious_hashes = {
        "4d186321c1a7f0f354b297e8914ab240",
        "098f6bcd4621d373cade4e832627b4f6",
        "1a37ea9aea86c42094e339bfe1daa6c6408efb4f3149798c6180a1ea021490fb"
        # Add more malicious hashes as needed
    }

    file_to_check = uploaded_file

    if flagg == 1:
        st.text('The file provided is malicious')
    else:
        st.text('The file provided is not malicious')



if st.button('Scan file'):
    main()
