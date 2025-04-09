import pandas as pd
import pickle
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, confusion_matrix

# Load the labeled data
data = pd.read_csv('labeled_packets.csv')

# Define encoding functions
def encode_ip(ip):
    ip_mapping = {
        '192.168.1.x': 1,  # Host Machine
        '192.168.1.x': 2,  # Web Server
        '192.168.1.x': 3,  # IDS
        '192.168.1.x': 4   # Attacker
    }
    return ip_mapping.get(ip, 0)  # 0 for unknown IPs

def encode_protocol(proto):
    if proto == 'TCP':
        return 1
    elif proto == 'UDP':
        return 2
    elif proto == 'ICMP':
        return 3
    else:
        return 0  # Unknown protocol

def encode_flags(flags):
    if flags == 'PA':
        return 1
    elif flags == 'S':
        return 2
    elif flags == 'SA':
        return 3
    elif flags == 'FA':
        return 4
    elif flags == 'R':
        return 5
    elif flags == 'RA':
        return 6
    elif flags == 'FPA':
        return 7
    else:
        return 0  # Unknown or missing flag

# Apply encoding to necessary columns
data['src_ip'] = data['src_ip'].apply(encode_ip)
data['dst_ip'] = data['dst_ip'].apply(encode_ip)
data['protocol'] = data['protocol'].apply(encode_protocol)
data['flags'] = data['flags'].apply(encode_flags)

# Features and Labels
X = data[['src_ip', 'dst_ip', 'src_port', 'dst_port', 'protocol', 'length', 'flags', 'ttl']]
y = data['label']


X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)


model = RandomForestClassifier()
model.fit(X_train, y_train)


y_pred = model.predict(X_test)
print("Accuracy:", model.score(X_test, y_test))
print("Classification Report:")
print(classification_report(y_test, y_pred))
print("Confusion Matrix:")
print(confusion_matrix(y_test, y_pred))


with open('ml_model.pkl', 'wb') as f:
    pickle.dump(model, f)

print("Trained model saved as 'ml_model.pkl'.")
