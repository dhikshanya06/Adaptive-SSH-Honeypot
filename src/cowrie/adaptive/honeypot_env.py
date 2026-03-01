import gymnasium as gym
from gymnasium import spaces
import numpy as np
from collections import deque
import random

class HoneypotEnv(gym.Env):
    def __init__(self):
        super().__init__()
        self.action_space = spaces.Discrete(3)
        self.observation_space = spaces.Box(
            low=0, high=1, shape=(105,), dtype=np.float32
        )
        self.reset()

    def reset(self, seed=None, options=None):
        super().reset(seed=seed)
        self.session_duration = 0
        self.command_history  = deque(maxlen=5)
        self.attacker_skill   = 0
        self.files_accessed   = 0
        self.bait_files       = 0
        self.is_connected     = True
        return self._get_state(), {}

    def step(self, action):
        if action == 0:
            stay_prob = 0.70; dl_prob = 0.05
        elif action == 1:
            stay_prob = 0.85; dl_prob = 0.20
        else:
            stay_prob = 0.65; dl_prob = 0.02

        stayed     = random.random() < stay_prob
        downloaded = stayed and random.random() < dl_prob
        reward = 0
        if stayed:
            self.session_duration += 10
            reward += 1
        if downloaded:
            reward += 10
        if not stayed:
            reward -= 100
        return self._get_state(), reward, not stayed, False, {}

    def _get_state(self):
        cmd_features = np.zeros(100, dtype=np.float32)
        for i, cmd in enumerate(self.command_history):
            for j, ch in enumerate(cmd[:20]):
                cmd_features[i * 20 + j] = ord(ch) / 127.0
        ctx = np.array([
            self.attacker_skill / 2.0,
            min(self.files_accessed / 10.0, 1.0),
            min(self.session_duration / 3600.0, 1.0),
            min(self.bait_files / 5.0, 1.0),
            1.0 if self.is_connected else 0.0
        ], dtype=np.float32)
        return np.concatenate([cmd_features, ctx])
