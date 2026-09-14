from app.skills.loader import skill_loader

class SkillRegistry:
    @staticmethod
    def get_context(agent_role: str) -> str:
        return skill_loader.get_skills_for_agent(agent_role)

skill_registry = SkillRegistry()
