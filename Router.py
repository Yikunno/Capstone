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
            open_ports = random.sample(range(20, 1025), k=random.randint(1, 3))  # 1–3 ports is normal
            devices.append({
                "ip": ip,
                "open_ports": open_ports
            })

        devices.append({
            "ip": f"10.0.0.{random.randint(1, 254)}",
            "open_ports": random.sample(range(1025, 65535), k=8)
        })
        devices.append({
            "ip": f"172.16.0.{random.randint(1, 254)}",
            "open_ports": list(range(20, 90))
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
            features = [ip_last_octet, num_ports]
            feature_list.append(features)
        return np.array(feature_list)

    def train_and_detect(self, devices):
        features = self.prepare_features(devices)
        self.model.fit(features)
        labels = self.model.labels_

        cluster_sizes = np.bincount(labels)
        anomaly_cluster = np.argmin(cluster_sizes)

        flagged = []
        for i, device in enumerate(devices):
            if labels[i] == anomaly_cluster:
                flagged.append(device)
        return flagged
#Execution

def main():
    router = SimulatedRouter()
    network_data = router.expose_data_for_scanner()
    devices = network_data["devices"]

    print("\n--- Network Devices ---")
    for d in devices:
        print(f"IP: {d['ip']}, Open Ports: {d['open_ports']}")

    detector = AnomalyDetector()
    flagged = detector.train_and_detect(devices)

    print("\n--- Flagged Misconfigured Devices ---")
    for d in flagged:
        print(f"IP: {d['ip']}, Open Ports: {d['open_ports']}")

if __name__ == "__main__":
    main()
