from pydantic import BaseModel, Field
from typing import List, Optional, Literal

class PatternItem(BaseModel):
    name: str
    regex: str
    case_sensitive: bool = False
    whole_word: bool = False

class DetectRequest(BaseModel):
    patterns: List[PatternItem] = Field(default_factory=list)

class Box(BaseModel):
    page: int
    x0: float
    y0: float
    x1: float
    y1: float
    matched_text: Optional[str] = None
    pattern_name: Optional[str] = None

class DetectResponse(BaseModel):
    total_matches: int
    boxes: List[Box]

class RedactRequest(BaseModel):
    boxes: List[Box]
    fill: Literal["black", "white"] = "black"
