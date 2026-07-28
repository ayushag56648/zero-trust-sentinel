const { PDFDocument, PDFName, PDFString } = require('pdf-lib');
const fs = require('fs');

async function createUncompressedTestPdf() {
    const pdfDoc = await PDFDocument.create();
    const page = pdfDoc.addPage([600, 400]);

    page.drawText('Zero Trust Sentinel - Verified Threat Test File', {
        x: 50,
        y: 320,
        size: 16
    });

    page.drawText('Click this link: http://malicious-phishing-test.com/login', {
        x: 50,
        y: 250,
        size: 12
    });

    // Inject a raw JavaScript OpenAction trigger into the Catalog
    const openActionDict = pdfDoc.context.obj({
        S: PDFName.of('JavaScript'),
        JS: PDFString.of('app.alert("Zero Trust Test Alert!");'),
    });

    pdfDoc.catalog.set(PDFName.of('OpenAction'), openActionDict);

    // ⚠️ CRITICAL FIX: useObjectStreams: false prevents FlateStream compression errors!
    const pdfBytes = await pdfDoc.save({ useObjectStreams: false });

    fs.writeFileSync('test_real_threat.pdf', pdfBytes);
    console.log('✅ Created test_real_threat.pdf without stream compression errors!');
}

createUncompressedTestPdf();