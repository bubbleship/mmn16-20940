class Simulator:

    def __init__(self, usernames):
        self.logger = CSVLogger(csv_path="attempts.csv")

        attacker1 = BruteForceAttacker(
            base_url="http://localhost:8000",
            max_length=4,
            logger=self.logger
        )

        attacker2 = RainbowTableAttacker(
            base_url="http://localhost:8000",
            max_length=4,
            logger=self.logger
        )

        self.attackers = [attacker1, attacker2]

        defense1 = DefenseSystem(
            sha_type="sha-256",
            rate_limit=4,
            logger=self.logger
        )

        self.defenseSystems = [defense1]
        self.usernames = usernames

    def simulateAttacks(self):
        for attacker in self.attackers:
            for defense in self.defenseSystems:
                for username in self.usernames:
                    attacker.getPassword(username)
