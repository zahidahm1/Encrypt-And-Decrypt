from flask import Flask, render_template, request
import base64
app = Flask(__name__)

def xor_encrypt_decrypt(data, key):
    encrypted_data = bytearray()
    key_length = len(key)

    for i in range(len(data)):
        encrypted_data.append(data[i] ^ key[i % key_length])

    return encrypted_data


@app.route('/')
def layout():
    return render_template('layout.html')


@app.route('/encrypt', methods=['POST'])
def encrypt():
    
    text = request.form.get('floatingTextarea2', '')
    key = request.form.get('key', '')
    action = request.form.get('action', '')

    data = text.encode('utf-8')
    key_bytes = key.encode('utf-8')

    if action == 'encrypt':
        encrypted_data = xor_encrypt_decrypt(data, key_bytes)
        encrypted_text = base64.b64encode(encrypted_data).decode('utf-8')
        return render_template('layout.html', encrypted_text=encrypted_text)
    elif action == 'decrypt':
        # Add decryption logic here
        decrypted_data = xor_encrypt_decrypt(base64.b64decode(text), key_bytes)
        decrypted_text = decrypted_data.decode('utf-8')
        return render_template('layout.html', decrypted_text=decrypted_text)

    
    else:
        # Handle other cases or errors
        return render_template('layout.html')
    






if __name__ == '__main__':
    app.run(debug=True)
