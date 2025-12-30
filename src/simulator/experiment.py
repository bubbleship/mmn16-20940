import time
import string
import random
import secrets
from typing import Dict, Any
import asyncio
from src.simulator.attackers import BruteForceAttacker, PasswordSprayAttacker
from simulator.pattern_sim import brute_force
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
        save_users(self.users)
        
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

    
        
    def _get_brute_force_generator(self, max_attempts: int = 1_000):
        """Get brute force password generator for weak passwords."""
        return brute_force(
            self.password_config.weak_alphabet, 
            self.password_config.weak_length, 
            max_attempts=max_attempts
        )
        
    async def _run_attacks(self, target: str, include_password_spray: bool = True) -> Dict[str, Any]:
        """Execute both brute force and password spray attacks, measuring execution time."""
        results = {}

        TIMEOUT_SECONDS = 30
        
        # Run brute force attack
        brute_force_gen = self._get_brute_force_generator()
        t0 = time.time()
        try:
            brute_force_summary = await asyncio.wait_for(
                self.brute_force_attacker.launch_attack(target, brute_force_gen),
                timeout=TIMEOUT_SECONDS
            )
        except asyncio.TimeoutError:
            brute_force_summary = {'status': 'timeout', 'message': 'Attack stopped early (Bcrypt/Timeout)'}

       # brute_force_summary = await self.brute_force_attacker.launch_attack(target, brute_force_gen)

        brute_force_time = time.time() - t0
        
        results.update({
            'brute_force': brute_force_summary,
            'brute_force_time': brute_force_time,
        })
        
        # Run password spray attack if requested
        if include_password_spray:
            t0 = time.time()
            try:
                password_spray_summary = await asyncio.wait_for(
                    self.password_spray_attacker.launch_attack(
                        self.password_spray_targets,
                        self.password_spray_collection
                    ),
                    timeout=TIMEOUT_SECONDS
                )
            except asyncio.TimeoutError:
                password_spray_summary = {'status': 'timeout', 'message': 'Spray stopped early (Bcrypt/Timeout)'}

            password_spray_time = time.time() - t0
            
            results.update({
                'password_spray': password_spray_summary,
                'password_spray_time': password_spray_time,
            })
        
        return results
        
    async def control_case(self, target: str) -> Dict[str, Any]:
        """Run the control case with Argon2ID hashing and no defenses."""
        hasher_config = HasherConfig(hasher_type=HasherType.Argon2ID)
        server.set_hasher(hasher_config)
        server.set_defenses()  # No defenses
        
        attack_results = await self._run_attacks(target, include_password_spray=True)
        
        return {
            'case': 'control',
            'hasher': hasher_config.hasher_type.value,
            'defenses': [],
            **attack_results
        }
    
    async def argon2id_pepper_hashing_case(self, target: str) -> Dict[str, Any]:
        """Argon2id hashing with a server-side Pepper."""
        hasher_config = HasherConfig(
            hasher_type=HasherType.Argon2ID,
            pepper="3f7a1b8e9d2c4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9"
        )

        server.set_hasher(hasher_config)
        server.set_defenses()

        attack_results = await self._run_attacks(target, include_password_spray=True)

        return {
            'case': 'argon2_pepper',
            'hasher': 'Argon2id+Pepper',
            'defenses': ['Pepper'],
            **attack_results
        }
        
    async def mfa_case(self, target: str) -> Dict[str, Any]:
        """Run the MFA defense case."""
        hasher_config = HasherConfig(hasher_type=HasherType.Argon2ID)
        server.set_hasher(hasher_config)
        server.set_defenses(MFADefenseConfig())
        
        attack_results = await self._run_attacks(target, include_password_spray=True)
        
        return {
            'case': 'mfa',
            'hasher': hasher_config.hasher_type.value,
            'defenses': ['MFA'],
            **attack_results
        }

    async def mfa_with_rate_limiting_case(self, target: str) -> Dict[str, Any]:
        """
        Literature Case: MFA combined with Rate Limiting.
        Prevents MFA exhaustion attacks and brute-forcing of the TOTP token.
        """
        hasher_config = HasherConfig(hasher_type=HasherType.Argon2ID)
        server.set_hasher(hasher_config)

        # Implementing both defenses as recommended in the literature review
        server.set_defenses(
            RateLimitDefenseConfig(rate=5, capacity=10),
            MFADefenseConfig()
        )

        attack_results = await self._run_attacks(target, include_password_spray=True)

        return {
            'case': 'mfa_plus_ratelimit',
            'hasher': 'Argon2id',
            'defenses': ['MFA', 'RateLimit'],
            **attack_results
        }
        
    async def rate_limit_case(self, target: str) -> Dict[str, Any]:
        """Run rate limiting defense case."""
        hasher_config = HasherConfig(hasher_type=HasherType.Argon2ID)
        server.set_hasher(hasher_config)
        server.set_defenses(RateLimitDefenseConfig(rate=10, capacity=20))
        
        attack_results = await self._run_attacks(target, include_password_spray=True)
        
        return {
            'case': 'rate_limit',
            'hasher': hasher_config.hasher_type.value,
            'defenses': ['RateLimit'],
            **attack_results
        }
        
    async def account_lockout_case(self, target: str) -> Dict[str, Any]:
        """Run account lockout defense case."""
        hasher_config = HasherConfig(hasher_type=HasherType.Argon2ID)
        server.set_hasher(hasher_config)
        server.set_defenses(AccountLockoutDefenseConfig(max_attempts=5))
        
        attack_results = await self._run_attacks(target, include_password_spray=True)
        
        return {
            'case': 'account_lockout',
            'hasher': hasher_config.hasher_type.value,
            'defenses': ['AccountLockout'],
            **attack_results
        }
        
    async def captcha_case(self, target: str) -> Dict[str, Any]:
        """Run CAPTCHA defense case."""
        hasher_config = HasherConfig(hasher_type=HasherType.Argon2ID)
        server.set_hasher(hasher_config)
        server.set_defenses(CaptchaDefenseConfig(max_attempts=5))
        
        attack_results = await self._run_attacks(target, include_password_spray=True)
        
        return {
            'case': 'captcha',
            'hasher': hasher_config.hasher_type.value,
            'defenses': ['CAPTCHA'],
            **attack_results
        }
        
    async def bcrypt_hasher_case(self, target: str) -> Dict[str, Any]:
        """Run the control case with BCrypt hasher instead of Argon2ID."""
        hasher_config = HasherConfig(hasher_type=HasherType.BCrypt)
        server.set_hasher(hasher_config)
        server.set_defenses()  # No defenses
        
        attack_results = await self._run_attacks(target, include_password_spray=True)
        
        return {
            'case': 'bcrypt_hasher',
            'hasher': hasher_config.hasher_type.value,
            'defenses': [],
            **attack_results
        }
        
    async def plaintext_hasher_case(self, target: str) -> Dict[str, Any]:
        """Run case with plaintext hasher (for comparison)."""
        hasher_config = HasherConfig(hasher_type=HasherType.PlainText)
        server.set_hasher(hasher_config)
        server.set_defenses()  # No defenses
        
        attack_results = await self._run_attacks(target, include_password_spray=True)
        
        return {
            'case': 'plaintext_hasher',
            'hasher': hasher_config.hasher_type.value,
            'defenses': [],
            **attack_results
        }

    async def lockout_with_captcha_case(self, target: str) -> Dict[str, Any]:
        """
        Literature-Based Combo: Account Lockout protected by CAPTCHA.
        As noted in the review, CAPTCHA prevents automated DoS attacks
        aimed at locking out legitimate users.
        """
        # Setting the secure baseline
        hasher_config = HasherConfig(hasher_type=HasherType.Argon2ID)
        server.set_hasher(hasher_config)

        # 1. Captcha starts after 3 failed attempts to stop bots.
        # 2. Lockout happens at 5 attempts (as per literature) as a final fail-safe.
        server.set_defenses(
            CaptchaDefenseConfig(max_attempts=3),
            AccountLockoutDefenseConfig(max_attempts=5)
        )

        # Running attacks - this will demonstrate how CAPTCHA blocks the bot
        # before it can trigger a full account lockout.
        attack_results = await self._run_attacks(target, include_password_spray=True)

        return {
            'case': 'lockout_with_captcha',
            'hasher': hasher_config.hasher_type.value,
            'defenses': ['CAPTCHA', 'Account Lockout'],
            **attack_results
        }

    async def lockout_with_captcha_case(self, target: str) -> Dict[str, Any]:
        """Defense combo: CAPTCHA protects against lockout-based DoS."""
        hasher_config = HasherConfig(hasher_type=HasherType.Argon2ID)
        server.set_hasher(hasher_config)

        # CAPTCHA at 3 attempts, Lockout at 5
        server.set_defenses(
            CaptchaDefenseConfig(max_attempts=3),
            AccountLockoutDefenseConfig(max_attempts=5)
        )

        attack_results = await self._run_attacks(target, include_password_spray=True)

        return {
            'case': 'lockout_with_captcha',
            'hasher': 'Argon2id',
            'defenses': ['CAPTCHA', 'Account Lockout'],
            **attack_results
        }

    async def total_protection_case(self, target: str) -> Dict[str, Any]:
        """Maximum security: All defenses enabled simultaneously."""
        hasher_config = HasherConfig(hasher_type=HasherType.Argon2ID)
        server.set_hasher(hasher_config)

        server.set_defenses(
            RateLimitDefenseConfig(rate=5, capacity=10),
            CaptchaDefenseConfig(max_attempts=3),
            AccountLockoutDefenseConfig(max_attempts=5),
            MFADefenseConfig()
        )

        attack_results = await self._run_attacks(target, include_password_spray=True)

        return {
            'case': 'total_protection',
            'hasher': 'Argon2id',
            'defenses': ['RateLimit', 'CAPTCHA', 'Account Lockout', 'MFA'],
            **attack_results
        }

    async def combined_defenses_case(self, target: str) -> Dict[str, Any]:
        """Run a case with multiple defenses combined."""
        hasher_config = HasherConfig(hasher_type=HasherType.Argon2ID)
        server.set_hasher(hasher_config)
        server.set_defenses(
            RateLimitDefenseConfig(rate=5, capacity=10),
            AccountLockoutDefenseConfig(max_attempts=5)
        )
        
        attack_results = await self._run_attacks(target, include_password_spray=True)
        
        return {
            'case': 'combined_defenses',
            'hasher': hasher_config.hasher_type.value,
            'defenses': ['RateLimit', 'AccountLockout'],
            **attack_results
        }
        
    async def run_all_cases(self) -> Dict[str, Any]:
        """Run all experiment cases and return comprehensive results."""
        results = {}
        
        # Setup server and users
        server.start(self.server_config)
        server.set_users(self.users)
        
        async with Client(self.client_config) as client:
            self._setup_attackers(client)
            
            # Select random weak user as target
            target = random.choice(self.weak_users)['username']
            print(f"Running experiment with target user: {target}")
            
            # Run all cases
            cases = [
                ('control', self.control_case),
                ('mfa', self.mfa_case),
                ('rate_limit', self.rate_limit_case),
                ('account_lockout', self.account_lockout_case),
                ('captcha', self.captcha_case),
                ('bcrypt_hasher', self.bcrypt_hasher_case),
                ('plaintext_hasher', self.plaintext_hasher_case),
                ('combined_defenses', self.combined_defenses_case),
                ('argon2id+pepper_hashing' , self.argon2id_pepper_hashing_case),
                ('mfa_with_rate_limiting',self.mfa_with_rate_limiting_case),
                ('lockout_with_captcha_case',self.lockout_with_captcha_case)
            ]
            
            for case_name, case_func in cases:
                print(f"Running {case_name} case...")
                try:
                    case_result = await case_func(target)
                    results[case_name] = case_result
                    print(f"✓ {case_name} case completed")
                except Exception as e:
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
    print("\n" + "="*50)
    print("EXPERIMENT RESULTS SUMMARY")
    print("="*50)
    
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
    
    return results