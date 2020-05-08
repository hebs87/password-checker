import requests
# Enables us to SHA1 hash a string
import hashlib
import sys


def request_api_data(query_password):
    """
    Checks the hashed password against password API to determine if it has been hacked
    """
    # Get the password API and store it in the url variable - the url followed by the password we want to test
    url = 'https://api.pwnedpasswords.com/range/' + query_password
    res = requests.get(url)
    if res.status_code != 200:
        raise RuntimeError(f'Error fetching: {res.status_code}, check the API and try again!')
    return res


def get_password_leaks(hashes, hash_to_check):
    """
    Checks our hashed password and loops through all the returned hash matches to determine the number of times
    a password has been hacked (the returned hashes follow the syntax of HASH:count
    """
    # Tuple comprehension - loops through each hash and splits it by the colon - returns tuple with hash and count
    hashes = (line.split(':') for line in hashes.text.splitlines())
    # Loop through the hashes tuples
    for h, count in hashes:
        # Check if the tail end of our hashes are equal to the hash
        if h == hash_to_check:
            return count

    return 0


def pwned_api_check(password):
    """
    Hashes the password and passed it into the request_api_data function
    Finally calls the get_password_leaks count and passes in the response from the request_api_data function to
    display the number of times a particular password has been hacked
    """
    # Hash the password, convert the sha1 object to hexadecimal readable text and then convert it to uppercase
    hashed_password = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
    # We only need to test the first 5 chars of the hashed password, so we store that in a variable and the remainder
    # of the password in another variable
    first_5, tail = hashed_password[:5], hashed_password[5:]
    # Then call the request_api_data function and pass in the first 5 characters
    response = request_api_data(first_5)

    # Call the get_password_leaks function and pass in the response object and also the tail (hash_to_check)
    return get_password_leaks(response, tail)


def main(args):
    """
    Main function that accepts the args, loops through them, calls the pwned_api_check function,
    passes in the password and tells the user if the password was found or not
    """
    for password in args:
        count = pwned_api_check(password)
        if count:
            print(f'{password} was found {count} times... you should probably change your password!')
        else:
            print(f'{password} was NOT found. Carry on!')

    return 'Done!'


if __name__ == '__main__':
    # Call the main function and pass in the args inputted by the user and exit once done
    sys.exit(main(sys.argv[1:]))
