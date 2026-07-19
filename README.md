# SuperAI6 IoT / MQTT Attack Detection (v13)

**Final result:** Public F1 `0.97434` · **Private F1 `0.98149`** (predicted attack: 2,871 / 10,000)
วิธี: **rule-based one-class novelty detection**  ไม่ใช้ ML

---

##  2 ไฟล์ (รัน 2 คำสั่ง)

```bash
# 1) สร้างคำตอบ 
python3 solution_v13_single_file.py      # -> submission_v13_single_file.csv

# 2) ดูที่มาของทุก threshold (พิมพ์ตัวเลขจากข้อมูลจริง)
python3 eda_thresholds.py
```
> ต้องมี `X_train.csv` และ `X_test.csv` (ไฟล์จากโจทย์) อยู่โฟลเดอร์เดียวกัน · ต้องมี `pandas`
> ตัวอย่างรันด้วย uv:  `uv run --python 3.12 --with pandas python3 solution_v13_single_file.py`

---

## ไฟล์ในชุดนี้

| ไฟล์ | หน้าที่ | พึ่งพา |
|---|---|---|
| **`solution_v13_single_file.py`** | คำตอบสุดท้าย -> rebuild ทั้ง pipeline (v6->v13) ในไฟล์เดียว | `X_train.csv`, `X_test.csv` เท่านั้น |
| **`eda_thresholds.py`** | รายงานที่มาของทุก threshold รันแล้วเห็นตัวเลขจากข้อมูล | import จาก single-file + ข้อมูล 2 ไฟล์ |

- `solution_v13_single_file.py` **ไม่อ่าน submission เก่า และไม่ใช้ Id list**  สร้าง label จากข้อมูลล้วน
- ทดสอบแล้ว: output **ตรงกับ `submission_v13.csv` ที่ส่งจริงทุกแถว (0 / 10,000 ต่างกัน)**

---

## Reproducibility (ยืนยันแล้ว)

```
solution_v13_single_file.py  ->  submission_v13_single_file.csv
เทียบกับ submission_v13.csv (Private 0.98149)  ->  rows differ: 0
```
Deterministic ทั้งหมด ไม่มีการสุ่ม รันกี่ครั้งก็ได้ผลเดิม

---

## Data handling


| งาน clean ทั่วไป | ทำไหม |
|---|---|
| ลบแถวซ้ำ / เติมค่าว่าง / ตัด outlier / scale / one-hot | **ไม่ทำ** |
| เก็บ `NaN` ไว้ (แปลว่า field นั้นไม่มีใน packet ชนิดนั้น) | ทำ เพราะอาจจะเป็นข้อมูลที่มีความหมาย |


---

## Thresholds มาจากไหน

ค่าคงที่ทั้งหมด (`MIN_DENSE_STREAM_RATIO=0.10`, `MIN_SESSION_ATTACK_RATIO=0.50`,
`SHORT_FRAME_LENGTHS={54,56}`, `SMALL_WINDOW 250–256`, `SKELETON_ACK_WINDOWS`) เป็น
**ไม่ใช่ค่ามาตรฐานของ TCP/MQTT และไม่ได้พิสูจน์ว่า optimal**
มาจาก 3 ทางร่วมกัน: distribution ของ Normal-train + EDA บน test ที่ไม่มี label + การทดลองบน public leaderboard โดยใช้ protocol semantics ช่วยจำกัดเงื่อนไข

**สำคัญ:** แต่ละค่าตกอยู่ใน **ช่องว่างกว้าง**ของข้อมูล (เช่น 10% ใช้ได้ทั้งช่วง 4.4–10.5%,
50% ใช้ได้ทั้งช่วง 11–67%) => เป็นเลขกลมๆที่อธิบายได้
รัน `eda_thresholds.py` เพื่อดูตัวเลขช่องว่างพวกนี้จากข้อมูลจริง

### Timeline

| วันที่ | สิ่งที่เกิด |
|---|---|
| **17 ก.ค.** | `testttt.py`, `testtttt.py`  EDA + คำนวณจำนวน attack ที่เหลือ |
| **18 ก.ค.** | docstring ใน `solution_v9–v13.py` บันทึกเหตุผล threshold (เช่น v9: *"ratio 4.4% ... 10-90% ... restore where ratio ≥ 10%"*) — ระหว่างแข่ง |
| **19 ก.ค.** | `eda_thresholds.py` — รวบรวมตัวเลขเดิมให้รันตรวจได้ (post-competition) |
เหตุผลมีมาตั้งแต่ตอนตัดสินใจจริง (docstrings 18 ก.ค.) · `eda_thresholds.py` เป็น **consolidated report** ไม่ใช่การหาเหตุผลใหม่ · อ่าน docstrings  เป็นหลักฐานหลัก แล้วรัน `eda_thresholds.py` เพื่อตรวจตัวเลข

---

## ข้อจำกัด

- ยังไม่พิสูจน์ข้าม capture ข้อมูลมาจากการเก็บชุดเดียว
- อุปกรณ์ใหม่ที่มีค่าปกติแปลกอาจถูกตีความผิดFP
- คะแนน Private พิสูจน์ผลระดับกลุ่มไม่สามารถยืนยัน label จริงรายแถวได้
