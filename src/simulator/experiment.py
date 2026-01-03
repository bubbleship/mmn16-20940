import time
import string
import random
import secrets
from typing import Dict, Any, Awaitable, Callable
import statistics
from src.simulator.postprocessor import run_postprocessing
from src.simulator.attackers import BruteForceAttacker, PasswordSprayAttacker
from src.simulator.pattern_sim import brute_force
from src.client.client import Client
from src.gen_users import generate_users, save_users
from src.server import server
from src.config.config import (
    ServerConfig, ClientConfig, PasswordConfig, MFADefenseConfig,
    RateLimitDefenseConfig, AccountLockoutDefenseConfig, CaptchaDefenseConfig,
    HasherConfig, HasherType
)


class ExperimentRunner:
    """Manages and executes the password security experiment across different scenarios."""

    def __init__(self):
        # Initialize configurations
        self.server_config = ServerConfig('0.0.0.0', 8080)
        self.client_config = ClientConfig(
            target_url='http://localhost:8080/login',
            admin_url='http://localhost:8080/admin'
        )
        self.password_config = PasswordConfig(
            weak_alphabet=string.ascii_lowercase,
            weak_length=6,
            medium_alphabet=string.ascii_lowercase + string.digits,
            medium_length=8,
            strong_alphabet=string.ascii_letters + string.digits + string.punctuation,
            strong_length=12
        )

        # Initialize user data
        self.users = []
        self.weak_users = []
        self.medium_users = []
        self.strong_users = []
        self.password_spray_collection = []
        self.password_spray_targets = []

        # Initialize attackers (will be set when the client is available)
        self.brute_force_attacker = None
        self.password_spray_attacker = None

    def setup_users(self):
        """Generate and categorize users for the experiment."""
        self.users = generate_users(30, self.password_config)
        save_users(self.users, dir_path='results')

        # Categorize users by password strength
        self.weak_users = list(filter(lambda u: u['strength_class'] == 'weak', self.users))
        self.medium_users = list(filter(lambda u: u['strength_class'] == 'medium', self.users))
        self.strong_users = list(filter(lambda u: u['strength_class'] == 'strong', self.users))

        # Set up password spray collections
        self.password_spray_collection = (
            # Padding passwords to simulate realistic password spray scenarios
                [''.join(secrets.choice(string.ascii_lowercase) for _ in range(6)) for _ in range(4)] +
                [user['password'] for user in self.weak_users] +
                [user['password'] for user in self.medium_users]
        )
        self.password_spray_targets = [user['username'] for user in self.users]

    def _setup_attackers(self, client: Client):
        """Initialize attacker instances with the client."""
        self.brute_force_attacker = BruteForceAttacker(client)
        self.password_spray_attacker = PasswordSprayAttacker(client)

    def _get_brute_force_generator(self, password_rig: str | None = None, max_attempts: int = 1_000,
                                   timeout: int | None = None):
        """Get brute force password generator for weak passwords."""
        return brute_force(
            self.password_config.weak_alphabet,
            self.password_config.weak_length,
            password_rig=password_rig,
            max_attempts=max_attempts,
            timeout=timeout
        )

    def _process_latency_stats(self, summary_dict: Dict[str, Any]):
        """Helper to replace raw latency lists with statistical summaries."""
        for user_data in summary_dict.values():
            if isinstance(user_data, dict) and 'latencies' in user_data:
                latencies = user_data['latencies']
                if latencies:
                    user_data['latency_median'] = statistics.median(latencies)
                    user_data['latency_std_dev'] = statistics.stdev(latencies) if len(latencies) > 1 else 0
                    user_data['latency_max'] = max(latencies)
                    user_data['latency_min'] = min(latencies)

                # delete the long list from summery to reduce JSON size
                del user_data['latencies']

    async def _run_attacks(self, target: str, brute_force_limit: int = 10_000,
                           brute_force_timeout: int | None = None) -> \
            Dict[str, Any]:
        """Execute both brute force and password spray attacks, measuring execution time."""
        results = {}

        # Run brute force attack
        brute_force_gen = self._get_brute_force_generator(max_attempts=brute_force_limit, timeout=brute_force_timeout)
        t0 = time.time()

        brute_force_summary = await self.brute_force_attacker.launch_attack(target, brute_force_gen)

        brute_force_time = time.time() - t0

        # Process Latency
        self._process_latency_stats(brute_force_summary)

        results.update({
            'brute_force': brute_force_summary,
            'brute_force_time': brute_force_time,
        })

        # Reset defense configuration before launching the next attack to prevent cross-contamination
        # of the results with the previous attack
        server.reset_defenses()

        # Run password spray attack
        t0 = time.time()
        password_spray_summary = await self.password_spray_attacker.launch_attack(
            self.password_spray_targets,
            self.password_spray_collection
        )
        password_spray_time = time.time() - t0

        # process latency
        self._process_latency_stats(password_spray_summary)

        results.update({
            'password_spray': password_spray_summary,
            'password_spray_time': password_spray_time,
        })

        return results

    async def baseline_plaintext_control(self, target: str) -> Dict[str, Any]:
        """
        Plaintext password storage vulnerability baseline. Demonstrates the complete
        lack of cryptographic protection to establish the worst-case scenario for
        comparative security analysis.
        """
        hasher_config = HasherConfig(hasher_type=HasherType.PlainText)
        server.set_hasher(hasher_config)
        server.set_defenses()  # No defenses

        attack_results = await self._run_attacks(target)

        return {
            'case': 'baseline_plaintext_control',
            'hasher': hasher_config,
            'defenses': [],
            **attack_results
        }

    async def baseline_bcrypt_legacy_control(self, target: str) -> Dict[str, Any]:
        """
        Baseline control case measuring attack performance against legacy BCrypt hashing
        without any defensive mechanisms. Establishes the fundamental security level provided
        by cryptographic hashing alone.
        """
        hasher_config = HasherConfig(hasher_type=HasherType.BCrypt)
        server.set_hasher(hasher_config)
        server.set_defenses()  # No defenses

        attack_results = await self._run_attacks(target, brute_force_timeout=5 * 60)  # 5 minutes

        return {
            'case': 'baseline_bcrypt_legacy_control',
            'hasher': hasher_config,
            'defenses': [],
            **attack_results
        }

    async def baseline_argon2id_control(self, target: str) -> Dict[str, Any]:
        """
        Baseline control case measuring attack performance against standard Argon2ID hashing
        without any defensive mechanisms. Establishes the fundamental security level provided
        by cryptographic hashing alone.
        """
        hasher_config = HasherConfig(hasher_type=HasherType.Argon2ID)
        server.set_hasher(hasher_config)
        server.set_defenses()  # No defenses

        attack_results = await self._run_attacks(target)

        return {
            'case': 'baseline_argon2id_control',
            'hasher': hasher_config,
            'defenses': [],
            **attack_results
        }

    async def baseline_argon2id_pepper_control(self, target: str) -> Dict[str, Any]:
        """
        Baseline control case measuring attack performance against Argon2ID hashing with pepper
        without any defensive mechanisms. Establishes the fundamental security level provided
        by cryptographic hashing alone.
        """
        hasher_config = HasherConfig(
            hasher_type=HasherType.Argon2ID,
            pepper=secrets.token_urlsafe(32)
        )

        server.set_hasher(hasher_config)
        server.set_defenses()

        attack_results = await self._run_attacks(target)

        return {
            'case': 'baseline_argon2id_pepper_control',
            'hasher': hasher_config,
            'defenses': [],
            **attack_results
        }

    async def mfa_defense(self, target: str) -> Dict[str, Any]:
        """
        Measures the effectiveness of Multifactor authentication against both brute force and
        password spray attacks.

        Settings: MFA defense mechanism and Argon2ID hashing.
        """
        hasher_config = HasherConfig(hasher_type=HasherType.Argon2ID)
        defenses_config = [MFADefenseConfig()]
        server.set_hasher(hasher_config)
        server.set_defenses(*defenses_config)

        attack_results = await self._run_attacks(target)

        return {
            'case': 'mfa_defense',
            'hasher': hasher_config,
            'defenses': defenses_config,
            **attack_results
        }

    async def rate_limiting_defense(self, target: str) -> Dict[str, Any]:
        """
        Measures the effectiveness of IP-based rate limiting against both brute force and password
        spray attacks.

        Settings: Rate limiting defense with rate=10 and capacity=20 and Argon2ID hashing.
        """
        hasher_config = HasherConfig(hasher_type=HasherType.Argon2ID)
        defenses_config = [RateLimitDefenseConfig(rate=10, capacity=20)]
        server.set_hasher(hasher_config)
        server.set_defenses(*defenses_config)

        attack_results = await self._run_attacks(target)

        return {
            'case': 'rate_limiting_defense',
            'hasher': hasher_config,
            'defenses': defenses_config,
            **attack_results
        }

    async def account_lockout_defense(self, target: str) -> Dict[str, Any]:
        """
        Measures the effectiveness of account lockout (or "username-based rate limiting") against
        both brute force and password spray attacks.

        Settings: Account lockout defense with max_attempts=5 and Argon2ID hashing.
        """
        hasher_config = HasherConfig(hasher_type=HasherType.Argon2ID)
        defenses_config = [AccountLockoutDefenseConfig(max_attempts=5)]
        server.set_hasher(hasher_config)
        server.set_defenses(*defenses_config)

        attack_results = await self._run_attacks(target)

        return {
            'case': 'account_lockout_defense',
            'hasher': hasher_config,
            'defenses': defenses_config,
            **attack_results
        }

    async def captcha_defense(self, target: str) -> Dict[str, Any]:
        """
        Measures the effectiveness of CAPTCHA against both brute force and password spray attacks.

        Settings: CAPTCHA defense with max_attempts=5 and Argon2ID hashing.
        """
        hasher_config = HasherConfig(hasher_type=HasherType.Argon2ID)
        defenses_config = [CaptchaDefenseConfig(max_attempts=5)]
        server.set_hasher(hasher_config)
        server.set_defenses(*defenses_config)

        attack_results = await self._run_attacks(target)

        return {
            'case': 'captcha_defense',
            'hasher': hasher_config,
            'defenses': defenses_config,
            **attack_results
        }

    async def mfa_rate_limiting_combination(self, target: str) -> Dict[str, Any]:
        """
        Measures the synergistic effectiveness of MFA and IP-based rate limiting against both brute
        force and password spray attacks.

        Settings: MFA defense mechanism, rate limiting defense with rate=5 and capacity=10, and Argon2ID hashing.
        """
        hasher_config = HasherConfig(hasher_type=HasherType.Argon2ID)
        defenses_config = [MFADefenseConfig(), RateLimitDefenseConfig(rate=5, capacity=10)]
        server.set_hasher(hasher_config)
        server.set_defenses(*defenses_config)

        attack_results = await self._run_attacks(target)

        return {
            'case': 'mfa_rate_limiting_combination',
            'hasher': hasher_config,
            'defenses': defenses_config,
            **attack_results
        }

    async def captcha_account_lockout_combination(self, target: str) -> Dict[str, Any]:
        """
        Measures the synergistic effectiveness of CAPTCHA and account lockout against both brute force
        and password spray attacks.
        Aims to prevent DoS from account lockout abuse by activating the CAPTCHA mechanism first.

        Settings: CAPTCHA defense with max_attempts=3, account lockout defense with max_attempts=5, and Argon2ID
        hashing.
        """
        # Setting the secure baseline
        hasher_config = HasherConfig(hasher_type=HasherType.Argon2ID)
        # 1. Captcha starts after 3 failed attempts to stop bots.
        # 2. Lockout happens at 5 attempts (as per literature) as a final fail-safe.
        defenses_config = [CaptchaDefenseConfig(max_attempts=3), AccountLockoutDefenseConfig(max_attempts=5)]
        server.set_hasher(hasher_config)
        server.set_defenses(*defenses_config)

        # Running attacks - this will demonstrate how CAPTCHA blocks the automated attack
        # before it can trigger a full account lockout.
        attack_results = await self._run_attacks(target)

        return {
            'case': 'captcha_lockout_hybrid_defense',
            'hasher': hasher_config,
            'defenses': defenses_config,
            **attack_results
        }

    async def rate_limit_account_lockout_combination(self, target: str) -> Dict[str, Any]:
        """
        Measures the synergistic effectiveness of IP-based rate limiting and account lockout against both
        brute force and password spray attacks.

        Settings: Rate limiting defense with rate=5 and capacity=10, and account lockout defense with max_attempts=5,
        and Argon2ID hashing.
        """
        hasher_config = HasherConfig(hasher_type=HasherType.Argon2ID)
        defenses_config = [RateLimitDefenseConfig(rate=5, capacity=10), AccountLockoutDefenseConfig(max_attempts=5)]
        server.set_hasher(hasher_config)
        server.set_defenses(*defenses_config)

        attack_results = await self._run_attacks(target)

        return {
            'case': 'rate_limit_account_lockout_combination',
            'hasher': hasher_config,
            'defenses': defenses_config,
            **attack_results
        }

    async def comprehensive_defense_stack(self, target: str) -> Dict[str, Any]:
        """
        Measures the synergistic effectiveness of all the defense mechanisms against both brute force and
        password spray attacks.
        Aims to test the cumulative effectiveness of layered security controls and identifies potential
        conflicts or performance impacts.

        Settings: MFA defense mechanism, rate limiting defense with rate=5 and capacity=10, account lockout
        defense with max_attempts=5, CAPTCHA defense with max_attempts=3, and Argon2ID hashing.
        """
        hasher_config = HasherConfig(hasher_type=HasherType.Argon2ID)
        defenses_config = [MFADefenseConfig(),
                           RateLimitDefenseConfig(rate=5, capacity=10),
                           AccountLockoutDefenseConfig(max_attempts=5),
                           CaptchaDefenseConfig(max_attempts=3)]
        server.set_hasher(hasher_config)
        server.set_defenses(*defenses_config)

        attack_results = await self._run_attacks(target)

        return {
            'case': 'comprehensive_defense_stack',
            'hasher': hasher_config,
            'defenses': defenses_config,
            **attack_results
        }

    async def run_all_cases(self) -> Dict[str, Any]:
        """
        Execute the password security experiment across multiple defense configurations.

        This method orchestrates a systematic evaluation of the password-based authentication mechanisms
        by running both brute force and password spray attacks against various combinations of cryptographic
        hashing algorithms and defensive mechanisms.
        The experiment targets a randomly selected user with weak password characteristics for brute force attacks to
        establish consistent baseline conditions.
        Password spray attacks are executed against all users to assess the effectiveness of defensive mechanisms. Unless
        stopped by a defense mechanism, password spray attacks should always succeed against weak and medium users.
        The defense mechanisms are being reset between cases to ensure a clean baseline for each test case.

        Returns:
            Dict[str, Any]: A comprehensive results dictionary where each key represents a test case
            identifier and each value contains the following structure:

            For successful test cases:
            {
                'case': str,                    # Test case identifier (e.g., 'baseline_argon2id_control')
                'hasher': HasherConfig,         # Cryptographic hashing configuration used
                'defenses': List[DefenseConfig], # List of defense mechanisms applied (empty for baseline cases)
                'brute_force': Dict[str, Dict[str, int]], # Brute force attack results by target username
                'brute_force_time': float,      # Execution time in seconds for brute force attack
                'password_spray': Dict[str, Dict[str, int]], # Password spray attack results by target username
                'password_spray_time': float    # Execution time in seconds for password spray attack
            }

            Attack result dictionaries contain counters for each authentication outcome:
            - 'SUCCESS': Successful authentication (attack succeeded)
            - 'INVALID_CREDENTIALS': Wrong password provided
            - 'USERNAME_NOT_FOUND': Target user does not exist
            - 'MFA': Multi-factor authentication challenge triggered
            - 'RATE_LIMIT': IP-based rate limiting activated
            - 'ACCOUNT_LOCKOUT': Account locked due to failed attempts
            - 'CAPTCHA': CAPTCHA challenge triggered
            - 'INTERNAL_SERVER_ERROR': Server-side error occurred

            For failed test cases (something went wrong during the experiment):
            {
                'error': str # Error message describing the failure cause
            }

            Test cases executed include baseline controls (plaintext, BCrypt, Argon2ID with/without pepper),
            individual defense mechanisms (MFA, rate limiting, account lockout, CAPTCHA), combination
            defenses (MFA+rate limiting, CAPTCHA+lockout, rate limiting+lockout), and comprehensive
            defense stack with all mechanisms enabled.
        """
        results = {}

        # Setup server and users
        server.start(self.server_config)
        server.set_users(self.users)

        async with Client(self.client_config) as client:
            self._setup_attackers(client)

            # Select random weak user as target
            target = random.choice(self.weak_users)['username']
            print(f"Running experiment with target user: {target}")

            # Define all test cases
            cases: list[Callable[[str], Awaitable[Dict[str, Any]]]] = [
                self.baseline_plaintext_control,
                self.baseline_bcrypt_legacy_control,
                self.baseline_argon2id_control,
                self.baseline_argon2id_pepper_control,
                self.mfa_defense,
                self.rate_limiting_defense,
                self.account_lockout_defense,
                self.captcha_defense,
                self.mfa_rate_limiting_combination,
                self.captcha_account_lockout_combination,
                self.rate_limit_account_lockout_combination,
                self.comprehensive_defense_stack,
            ]

            for case_func in cases:
                print(f"Running {case_func.__name__} case...")
                try:
                    case_result = await case_func(target)
                    case_name = case_result['case']
                    results[case_name] = case_result
                    print(f"✓ {case_name} case completed")
                except Exception as e:
                    case_name = case_func.__name__
                    print(f"✗ {case_name} case failed: {str(e)}")
                    results[case_name] = {'error': str(e)}

        return results


async def run_experiment():
    """Entry point for running the complete password security experiment."""
    print("Starting password security experiment...")

    # Initialize and setup experiment
    experiment = ExperimentRunner()
    experiment.setup_users()

    print(f"Generated {len(experiment.users)} users:")
    print(f"  - Weak passwords: {len(experiment.weak_users)}")
    print(f"  - Medium passwords: {len(experiment.medium_users)}")
    print(f"  - Strong passwords: {len(experiment.strong_users)}")
    print()

    # Run all experimental cases
    results = await experiment.run_all_cases()

    # Display summary
    print("\n" + "=" * 50)
    print("EXPERIMENT RESULTS SUMMARY")
    print("=" * 50)

    for case_name, case_result in results.items():
        if 'error' in case_result:
            print(f"{case_name.upper()}: FAILED - {case_result['error']}")
        else:
            print(f"{case_name.upper()}:")
            print(f"  Hasher: {case_result.get('hasher', 'N/A')}")
            print(f"  Defenses: {case_result.get('defenses', [])}")
            if 'brute_force_time' in case_result:
                print(f"  Brute Force Time: {case_result['brute_force_time']:.2f}s")
            if 'password_spray_time' in case_result:
                print(f"  Password Spray Time: {case_result['password_spray_time']:.2f}s")
            print()

    # Run postprocessing
    enhanced_results = run_postprocessing(
        results=results,
        users=experiment.users,
        password_config=experiment.password_config,
        output_dir="results"
    )

    return enhanced_results
