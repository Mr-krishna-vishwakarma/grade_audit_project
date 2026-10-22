import io
import json
import hashlib
from typing import Optional
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, StreamingResponse
from pydantic import BaseModel
import pymysql
import qrcode
from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, Image as RLImage
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle

app = FastAPI(title="Tamper-Evident Academic Credential Engine")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# --- DATABASE CONNECTION ---
DB_CONFIG = {
    "host": "localhost",
    "user": "root",
    "password": "Krishn@1586",  # <-- Verify your MySQL root password here
    "database": "grade_audit_system",
    "cursorclass": pymysql.cursors.DictCursor,
    "autocommit": False
}

def get_db():
    return pymysql.connect(**DB_CONFIG)

# --- REQUEST SCHEMAS ---
class GradeUpdateRequest(BaseModel):
    grade_id: str
    letter_grade: str
    grade_points: float
    audit_reason: str
    user: str

class TamperRequest(BaseModel):
    audit_id: int
    forged_grade: str

# --- API ENDPOINTS ---

@app.get("/api/transcript/{student_id}")
def get_transcript(student_id: str):
    conn = get_db()
    try:
        with conn.cursor() as cursor:
            query = """
                SELECT 
                    s.roll_number, u.full_name as student_name, s.department,
                    c.course_code, c.title as course_title, c.credits,
                    g.id as grade_id, g.letter_grade, g.grade_points, g.updated_at
                FROM enrollments e
                JOIN students s ON e.student_id = s.id
                JOIN users u ON s.user_id = u.id
                JOIN courses c ON e.course_id = c.id
                JOIN grades g ON e.id = g.enrollment_id
                WHERE s.id = %s;
            """
            cursor.execute(query, (student_id,))
            records = cursor.fetchall()

            if not records:
                raise HTTPException(status_code=404, detail="Student record not found")

            total_credits = sum(r["credits"] for r in records)
            weighted_points = sum(r["credits"] * float(r["grade_points"]) for r in records)
            cgpa = round(weighted_points / total_credits, 2) if total_credits > 0 else 0.0

            cursor.callproc("verify_student_chain", (student_id,))
            verification = cursor.fetchall()
            
            is_compromised = any(node["status"] == "TAMPERED" for node in verification)

            return {
                "student_info": {
                    "roll_number": records[0]["roll_number"],
                    "name": records[0]["student_name"],
                    "department": records[0]["department"],
                    "cgpa": cgpa
                },
                "status": "COMPROMISED" if is_compromised else "CRYPTOGRAPHICALLY_VERIFIED",
                "grades": records
            }
    finally:
        conn.close()


@app.get("/api/timeline/{student_id}")
def get_audit_timeline(student_id: str):
    conn = get_db()
    try:
        with conn.cursor() as cursor:
            query = """
                SELECT 
                    a.audit_id, a.operation, a.letter_grade, a.grade_points,
                    a.reason, a.modified_by, a.entry_timestamp, 
                    a.prev_hash, a.row_hash, c.course_code
                FROM grade_audit_chain a
                JOIN courses c ON a.course_id = c.id
                WHERE a.student_id = %s
                ORDER BY a.audit_id ASC;
            """
            cursor.execute(query, (student_id,))
            return cursor.fetchall()
    finally:
        conn.close()


@app.post("/api/grades/update")
def update_grade(req: GradeUpdateRequest):
    conn = get_db()
    try:
        with conn.cursor() as cursor:
            cursor.execute("SET @audit_reason = %s;", (req.audit_reason,))
            cursor.execute("SET @audit_user = %s;", (req.user,))
            
            update_sql = """
                UPDATE grades 
                SET letter_grade = %s, grade_points = %s 
                WHERE id = %s;
            """
            cursor.execute(update_sql, (req.letter_grade, req.grade_points, req.grade_id))
            conn.commit()
            return {"status": "SUCCESS", "message": "Grade updated and hashed into ledger."}
    except Exception as e:
        conn.rollback()
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        conn.close()


@app.get("/api/verify/{student_id}")
def run_verification(student_id: str):
    conn = get_db()
    try:
        with conn.cursor() as cursor:
            cursor.callproc("verify_student_chain", (student_id,))
            results = cursor.fetchall()
            
            all_valid = all(r["status"] == "VERIFIED" for r in results)
            return {
                "overall_status": "SECURE" if all_valid else "CORRUPTED",
                "total_blocks": len(results),
                "chain_nodes": results
            }
    finally:
        conn.close()


@app.post("/api/demo/tamper")
def simulate_tamper_attack(req: TamperRequest):
    conn = get_db()
    try:
        with conn.cursor() as cursor:
            cursor.execute("DROP TRIGGER IF EXISTS tripwire_audit_no_update;")
            cursor.execute(
                "UPDATE grade_audit_chain SET letter_grade = %s WHERE audit_id = %s;",
                (req.forged_grade, req.audit_id)
            )
            tripwire_sql = """
            CREATE TRIGGER tripwire_audit_no_update
            BEFORE UPDATE ON grade_audit_chain
            FOR EACH ROW
            BEGIN
                SIGNAL SQLSTATE '45000'
                SET MESSAGE_TEXT = 'SECURITY BREACH: grade_audit_chain is an immutable ledger. Updates are forbidden.';
            END;
            """
            cursor.execute(tripwire_sql)
            conn.commit()
            
            return {
                "attack_status": "TAMPER_INJECTED",
                "message": f"Attacker modified Audit ID #{req.audit_id} to '{req.forged_grade}'."
            }
    except Exception as e:
        conn.rollback()
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        conn.close()


# --- PDF TRANSCRIPT & QR CODE EXPORT ---
@app.get("/api/transcript/{student_id}/export-pdf")
def export_pdf(student_id: str):
    conn = get_db()
    try:
        with conn.cursor() as cursor:
            # Query transcript data
            query = """
                SELECT 
                    s.roll_number, u.full_name as student_name, s.department,
                    c.course_code, c.title as course_title, c.credits,
                    g.letter_grade, g.grade_points
                FROM enrollments e
                JOIN students s ON e.student_id = s.id
                JOIN users u ON s.user_id = u.id
                JOIN courses c ON e.course_id = c.id
                JOIN grades g ON e.id = g.enrollment_id
                WHERE s.id = %s;
            """
            cursor.execute(query, (student_id,))
            records = cursor.fetchall()

            if not records:
                raise HTTPException(status_code=404, detail="Student not found")

            # Check audit chain state
            cursor.callproc("verify_student_chain", (student_id,))
            verification = cursor.fetchall()
            is_valid = all(node["status"] == "VERIFIED" for node in verification)
            latest_hash = verification[-1]["stored_hash"] if verification else "000000"

            # GPA computation
            total_credits = sum(r["credits"] for r in records)
            weighted_points = sum(r["credits"] * float(r["grade_points"]) for r in records)
            cgpa = round(weighted_points / total_credits, 2) if total_credits > 0 else 0.0

            # Build Canonical Verification Payload for QR Code
            qr_payload = {
                "roll_number": records[0]["roll_number"],
                "cgpa": cgpa,
                "latest_ledger_hash": latest_hash,
                "chain_status": "VERIFIED" if is_valid else "TAMPERED",
                "issuer": "Academic Examination Cell"
            }
            qr_content = json.dumps(qr_payload, separators=(',', ':'))

            # Generate QR Code image in memory
            qr = qrcode.QRCode(box_size=3, border=2)
            qr.add_data(qr_content)
            qr.make(fit=True)
            qr_img = qr.make_image(fill_color="black", back_color="white")
            qr_buffer = io.BytesIO()
            qr_img.save(qr_buffer, format="PNG")
            qr_buffer.seek(0)

            # Build PDF Document
            pdf_buffer = io.BytesIO()
            doc = SimpleDocTemplate(pdf_buffer, pagesize=letter, leftMargin=36, rightMargin=36, topMargin=36, bottomMargin=36)
            styles = getSampleStyleSheet()
            elements = []

            # Document Title
            title_style = ParagraphStyle('TitleStyle', parent=styles['Heading1'], fontSize=18, textColor=colors.HexColor("#1e293b"), alignment=1)
            sub_style = ParagraphStyle('SubStyle', parent=styles['Normal'], fontSize=9, textColor=colors.HexColor("#64748b"), alignment=1)
            elements.append(Paragraph("OFFICIAL ACADEMIC TRANSCRIPT", title_style))
            elements.append(Paragraph("Cryptographically Audited Grade Engine - Tamper-Evident Record", sub_style))
            elements.append(Spacer(1, 15))

            # Student Metadata Table
            meta_data = [
                [Paragraph("<b>Student Name:</b>", styles['Normal']), Paragraph(records[0]["student_name"], styles['Normal']),
                 Paragraph("<b>Roll Number:</b>", styles['Normal']), Paragraph(records[0]["roll_number"], styles['Normal'])],
                [Paragraph("<b>Department:</b>", styles['Normal']), Paragraph(records[0]["department"], styles['Normal']),
                 Paragraph("<b>Cumulative GPA:</b>", styles['Normal']), Paragraph(f"<b>{cgpa} / 10.00</b>", styles['Normal'])]
            ]
            meta_table = Table(meta_data, colWidths=[100, 170, 100, 170])
            meta_table.setStyle(TableStyle([
                ('BACKGROUND', (0,0), (-1,-1), colors.HexColor("#f8fafc")),
                ('BOX', (0,0), (-1,-1), 1, colors.HexColor("#cbd5e1")),
                ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
                ('BOTTOMPADDING', (0,0), (-1,-1), 6),
                ('TOPPADDING', (0,0), (-1,-1), 6),
            ]))
            elements.append(meta_table)
            elements.append(Spacer(1, 15))

            # Course Records Table
            table_rows = [["Course Code", "Course Title", "Credits", "Grade", "Grade Points"]]
            for r in records:
                table_rows.append([r["course_code"], r["course_title"], str(r["credits"]), r["letter_grade"], f"{float(r['grade_points']):.2f}"])

            grade_table = Table(table_rows, colWidths=[80, 260, 60, 60, 80])
            grade_table.setStyle(TableStyle([
                ('BACKGROUND', (0,0), (-1,0), colors.HexColor("#0f172a")),
                ('TEXTCOLOR', (0,0), (-1,0), colors.whitesmoke),
                ('ALIGN', (0,0), (-1,-1), 'CENTER'),
                ('ALIGN', (1,1), (1,-1), 'LEFT'),
                ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor("#cbd5e1")),
                ('TOPPADDING', (0,0), (-1,-1), 6),
                ('BOTTOMPADDING', (0,0), (-1,-1), 6),
            ]))
            elements.append(grade_table)
            elements.append(Spacer(1, 20))

            # Security Verification Section + QR Code
            security_header = "CRYPTOGRAPHIC AUDIT VERIFICATION SEAL"
            status_text = "STATUS: LEDGER VERIFIED (INTACT)" if is_valid else "STATUS: INTEGRITY ALERT (TAMPERED)"
            status_color = "#047857" if is_valid else "#b91c1c"

            sec_info = [
                [
                    Paragraph(f"<b>{security_header}</b><br/><br/>"
                              f"<font color='{status_color}'><b>{status_text}</b></font><br/>"
                              f"<b>Latest Merkle/Block Hash:</b><br/><font size='7' face='Courier'>{latest_hash}</font><br/><br/>"
                              f"<font size='8' color='#64748b'>Scan the verification QR code using any scanner to validate this document's mathematical fingerprint against the registry log.</font>", styles['Normal']),
                    RLImage(qr_buffer, width=100, height=100)
                ]
            ]
            sec_table = Table(sec_info, colWidths=[430, 110])
            sec_table.setStyle(TableStyle([
                ('BOX', (0,0), (-1,-1), 1, colors.HexColor("#94a3b8")),
                ('BACKGROUND', (0,0), (-1,-1), colors.HexColor("#f1f5f9")),
                ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
                ('PADDING', (0,0), (-1,-1), 8),
            ]))
            elements.append(sec_table)

            doc.build(elements)
            pdf_buffer.seek(0)

            return StreamingResponse(
                pdf_buffer,
                media_type="application/pdf",
                headers={"Content-Disposition": f"attachment; filename=transcript_{records[0]['roll_number']}.pdf"}
            )
    finally:
        conn.close()


@app.get("/", response_class=HTMLResponse)
def index_page():
    with open("dashboard.html", "r", encoding="utf-8") as f:
        return f.read()