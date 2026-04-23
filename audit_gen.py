from fpdf import FPDF

class SecurityTestPDF(FPDF):
    def create_audit_file(self, filename):
        self.add_page()
        self.set_font("Arial", size=12)
        self.cell(200, 10, txt="Security Audit Test Case: Metadata Indicators", ln=True, align='C')
        
        # We are adding a 'dictionary' that contains the tags 
        # but we frame it as 'Metadata for Audit'
        audit_data = {
            "/Type": "/Action",
            "/S": "/JavaScript",
            "/JS": '(app.alert("Zero-Trust Sentinel: Active Content Detected");)',
            "/OpenAction": "True"
        }
        
        # This injects the tags into the PDF structure properly 
        # so it's not 'junk' data anymore.
        self.add_action(action=audit_data["/JS"])
        self.output(filename)
        print(f"Successfully generated {filename} for detection testing.")

test = SecurityTestPDF()
test.create_audit_file("detection_test_v3.pdf")