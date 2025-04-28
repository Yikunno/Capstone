import random
import numpy as np
from sklearn.cluster import KMeans

#Router Simulator
class SimulatedRouter:
    def __init__(self, name="SimulatedRouter"):
        self.name = name
        self.devices = self.generate_devices()

    def generate_devices(self, num_devices=10):

        devices = []
        for _ in range(num_devices):
            ip = f"192.168.1.{random.randint(2, 254)}"
            open_ports = random.sample(range(20, 1025), k=random.randint(1, 3))
            weak_password = random.choice([True, False])
            device = {
                "ip": ip,
                "open_ports": open_ports,
                "weak_password": weak_password
            }
            devices.append(device)

        devices.append({
            "ip": f"10.0.0.{random.randint(1, 254)}",  # weird IP range
            "open_ports": random.sample(range(1025, 65535), k=random.randint(5, 10)),
            "weak_password": True
        })

        devices.append({
            "ip": f"172.16.0.{random.randint(1, 254)}",  # another odd IP
            "open_ports": list(range(20, 80)),  # a lot of open ports
            "weak_password": True
        })

        return devices

    def expose_data_for_scanner(self):
        return {
            "router_name": self.name,
            "devices": self.devices
        }

#ML Model
class AnomalyDetector:
    def __init__(self, n_clusters=2):
        self.model = KMeans(n_clusters=n_clusters)
    def prepare_features(self, devices):
        feature_list = []
        for device in devices:
            ip_last_octet = int(device["ip"].split(".")[-1])
            num_ports = len(device["open_ports"])
            has_weak_password = int(device["weak_password"])
            features = [ip_last_octet, num_ports, has_weak_password]
            feature_list.append(features)
        return np.array(feature_list)

    def train_and_detect(self, devices):
        features = self.prepare_features(devices)
        self.model.fit(features)
        labels = self.model.labels_

        cluster_sizes = np.bincount(labels)
        anomaly_cluster = np.argmin(cluster_sizes)

        anomalies = []
        for i, device in enumerate(devices):
            if labels[i] == anomaly_cluster:
                anomalies.append(device)
        return anomalies

#Execution
def main():
    router = SimulatedRouter()
    network_data = router.expose_data_for_scanner()

    print("\n--- Simulated Router Devices ---")
    for device in network_data["devices"]:
        print(device)

    detector = AnomalyDetector()
    anomalies = detector.train_and_detect(network_data["devices"])

    print("\n--- Detected Anomalous Devices ---")
    for anomaly in anomalies:
        print(anomaly)

if __name__ == "__main__":
    main()
