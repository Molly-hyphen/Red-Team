import os
from typing import Dict, List, Optional

class SkillLoader:
    def __init__(self, definitions_dir: Optional[str] = None):
        if not definitions_dir:
            base_dir = os.path.dirname(os.path.abspath(__file__))
            definitions_dir = os.path.join(base_dir, "definitions")
        self.definitions_dir = definitions_dir
        self.skills: Dict[str, str] = {}
        self.load_all()

    def load_all(self):
        if not os.path.exists(self.definitions_dir):
            return
        for file in os.listdir(self.definitions_dir):
            if file.endswith(".md"):
                skill_name = file.replace(".md", "")
                filepath = os.path.join(self.definitions_dir, file)
                try:
                    with open(filepath, "r", encoding="utf-8") as f:
                        self.skills[skill_name] = f.read()
                except Exception:
                    pass

    def get_skill(self, name: str) -> Optional[str]:
        return self.skills.get(name)

    def get_skills_for_agent(self, agent_role: str) -> str:
        """Dynamically load only the relevant skills for an agent to prevent prompt bloating."""
        mapping = {
            "ReconAgent": ["recon"],
            "WebAgent": ["xss", "injection", "authentication"],
            "APIAgent": ["authorization", "injection", "ssrf"],
            "AuthAgent": ["authentication", "authorization"],
            "AuthorizationAgent": ["authorization"],
            "BusinessLogicAgent": ["business_logic"],
            "SourceAnalysisAgent": ["injection", "authorization", "xss"],
            "ValidatorAgent": ["injection", "authorization", "xss", "ssrf"]
        }
        
        relevant_keys = mapping.get(agent_role, ["authentication", "authorization", "injection"])
        loaded_texts = []
        for k in relevant_keys:
            if k in self.skills:
                loaded_texts.append(self.skills[k])
        return "\n\n---\n\n".join(loaded_texts)

skill_loader = SkillLoader()
