from dataclasses import dataclass, field
from typing import Optional, Dict

@dataclass
class DredgeConfig:
    region_name: Optional[str] = None
    default_tags: Dict[str, str] = field(default_factory=dict)
    dry_run: bool = False
