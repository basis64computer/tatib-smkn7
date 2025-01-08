function historyToTableArray(history) {
    let array = [];
    for (var i=0; i<history.length; i++) {
        if (history[i].kurang) {
            array.push([(i+1).toString(), -history[i].kurang, history[i].description, formatDate(new Date(history[i].timestamp), "dd MMMM yyyy")]);
        } else {
            array.push([(i+1).toString(), "+" + history[i].tambah, history[i].description, formatDate(new Date(history[i].timestamp), "dd MMMM yyyy")]);
        }
    }
    return array;
}

function siswaToTableArray(siswa) {
    let array = [];
    for (var i=0; i<siswa.length; i++) {
        array.push([(i+1).toString(), siswa[i].nisn, siswa[i].name, siswa[i].poin]);
    }
    return array;
}

function cetakLaporanKelas(kelas, data) {
    const doc = new jspdf.jsPDF();

	// Invoice Header
	let positionY = 30;
	doc.setFontSize(20);
	doc.text("POIN SISWA", doc.internal.pageSize.getWidth()/2-21, positionY-10);

	doc.setFontSize(12);
	//doc.text("Nama", 20, positionY+15);
	//doc.text(":", 35, positionY+15);
	//doc.text("Naufal Raissa Almaydy", 50, positionY+15);

	doc.text("Kelas", 20, positionY+5);
	doc.text(":", 35, positionY+5);
	doc.text(kelas, 50, positionY+5);

	// Invoice Table
	doc.autoTable({
	    startY: 40,
	    styles : { halign : 'center', fontSize: 10, cellPadding: 0.5}, 
	    headStyles :{fillColor : [255, 255, 255], textColor: [0, 0, 0]},
	    alternateRowStyles: {fillColor : [255, 255, 255]},
	    tableLineColor: [0, 0, 0],
	    tableLineWidth: 0.1,
	    theme: 'grid',
	    head: [['No', 'NISN', 'Nama', 'Sisa Poin']],
	    body: siswaToTableArray(data),
	});

	// Invoice Total
	let finalY = doc.previousAutoTable.finalY + 50; // The y position after the table
	doc.setFontSize(12);
	//doc.text('Samarinda, 11 September 2025', 120, finalY + 5);
	//doc.text('Wali kelas,', 120, finalY + 10);
	//doc.text('Abdul Haris, S.Pd', 120, finalY + 40)
	//const textWidth = doc.getTextWidth();
	//doc.line(x, y, x + textWidth, finalY + 45);
	

	// Footer
	doc.setFontSize(10);
	//doc.text('Thank you for your business!', 20, 280);
	doc.text('Tatib SMK Negeri 7 Samarinda', 20, 285);

	// Save the PDF
	window.open(doc.output('datauristring'));
}

function cetakLaporanSiswa(nama, kelas, nisn, absen, pelanggaran, waliKelas) {
    const doc = new jspdf.jsPDF();

	// Invoice Header
	let positionY = 30;
	doc.setFontSize(20);
	doc.text("RIWAWAT PEMOTONGAN POIN", doc.internal.pageSize.getWidth()/2-50, positionY);

	doc.setFontSize(12);
	doc.text("Nama", 20, positionY+15);
	doc.text(":", 35, positionY+15);
	doc.text(nama, 50, positionY+15);

	doc.text("Kelas", 20, positionY+20);
	doc.text(":", 35, positionY+20);
	doc.text(kelas, 50, positionY+20);

    doc.text("Absen", 20, positionY+25);
	doc.text(":", 35, positionY+25);
	doc.text(absen, 50, positionY+25);

    doc.text("NISN", 20, positionY+30);
	doc.text(":", 35, positionY+30);
	doc.text(nisn, 50, positionY+30);
	// Invoice Table
	doc.autoTable({
	    startY: 80,
	    styles : { halign : 'center'}, 
	    headStyles :{fillColor : [255, 255, 255], textColor: [0, 0, 0]},
	    alternateRowStyles: {fillColor : [255, 255, 255]},
	    didParseCell: function (data) {
	        if(data.section === 'body' && data.cell.raw < 0){
	            data.cell.styles.textColor = "red";
	        } else if(data.section === 'Poin' && data.cell.raw >= 0) {
	            data.cell.styles.textColor = "green";
	        }
	    },
	    tableLineColor: [0, 0, 0],
	    tableLineWidth: 0.1,
	    theme: 'grid',
	    head: [['No', 'poin', 'Pelanggaran', 'Tanggal']],
	    body: historyToTableArray(pelanggaran),
	});

	// Invoice Total
	let finalY = doc.previousAutoTable.finalY + 30; // The y position after the table
	doc.setFontSize(12);
	doc.text('Samarinda, ' + formatDate(new Date(), 'dd MMMM yyyy'), 120, finalY + 5);
	doc.text('Wali kelas,', 120, finalY + 10);
	doc.text(waliKelas, 120, finalY + 40)
	//const textWidth = doc.getTextWidth();
	//doc.line(x, y, x + textWidth, finalY + 45);
	

	// Footer
	doc.setFontSize(10);
	//doc.text('Thank you for your business!', 20, 280);
	doc.text('Tatib SMK Negeri 7 Samarinda', 20, 285);

	// Save the PDF
	window.open(doc.output('datauristring'));
}
