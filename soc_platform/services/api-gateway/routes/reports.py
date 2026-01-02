from fastapi import APIRouter

router = APIRouter()

@router.post("/generate")
async def generate_report():
    """Generate security report"""
    return {"message": "Report generation - to be implemented"}

@router.get("/{report_id}")
async def get_report(report_id: int):
    """Get generated report"""
    return {"report_id": report_id}
