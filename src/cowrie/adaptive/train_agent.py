import sys
sys.path.insert(0, '/home/cowrie/Adaptive-SSH-Honeypot/src')

from cowrie.adaptive.honeypot_env import HoneypotEnv
from stable_baselines3 import PPO
from stable_baselines3.common.env_util import make_vec_env
import os

def train():
    print("[*] Creating environment...")
    env = make_vec_env(HoneypotEnv, n_envs=4)
    print("[*] Building PPO agent...")
    model = PPO(
        "MlpPolicy",
        env,
        verbose=1,
        learning_rate=3e-4,
        n_steps=2048,
        batch_size=64,
        n_epochs=10,
        gamma=0.99
    )
    print("[*] Training for 100,000 steps...")
    model.learn(total_timesteps=100_000, progress_bar=True)
    os.makedirs("models", exist_ok=True)
    model.save("models/honeypot_ppo_v1")
    print("[*] DONE! Model saved!")

if __name__ == "__main__":
    train()
