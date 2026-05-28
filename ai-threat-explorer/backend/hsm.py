class EntrustShieldHSMSimulator:
    """A minimal stub simulating an HSM device.
    Provides a get_status method used by the Streamlit UI.
    """
    def __init__(self, db=None):
        self.db = db
        # Static mock status values
        self._status = {
            "temperature": "45°C",
            "sensors": "OK",
            "model": "Entrust Shield 2.0",
            "firmware": "v1.3.7",
            "fips_compliance": "FIPS 140-2 L3",
            "root_cert_expiry": "2025-12-31T23:59:59Z"
        }

    def get_status(self):
        """Return a dictionary of HSM status information.
        The UI expects keys: temperature, sensors, model, firmware, fips_compliance, root_cert_expiry.
        """
        return self._status
