function formatDate(date, format, utc) {
    var MMMM = ["\x00", "Januari", "Februari", "Maret", "April", "Mei", "Juni", "Juli", "Agustus", "September", "Oktober", "November", "Desember"];
    var MMM = ["\x01", "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];
    var dddd = ["\x02", "Minggu", "Senin", "Selasa", "Rabu", "Kamis", "Jumat", "Sabtu"];
    var ddd = ["\x03", "Min", "Sen", "Sel", "Rab", "Kam", "Jum", "Sab"];

    function ii(i, len) {
        var s = i + "";
        len = len || 2;
        while (s.length < len) s = "0" + s;
        return s;
    }

    var y = utc ? date.getUTCFullYear() : date.getFullYear();
    format = format.replace(/(^|[^\\])yyyy+/g, "$1" + y);
    format = format.replace(/(^|[^\\])yy/g, "$1" + y.toString().substr(2, 2));
    format = format.replace(/(^|[^\\])y/g, "$1" + y);

    var M = (utc ? date.getUTCMonth() : date.getMonth()) + 1;
    format = format.replace(/(^|[^\\])MMMM+/g, "$1" + MMMM[0]);
    format = format.replace(/(^|[^\\])MMM/g, "$1" + MMM[0]);
    format = format.replace(/(^|[^\\])MM/g, "$1" + ii(M));
    format = format.replace(/(^|[^\\])M/g, "$1" + M);

    var d = utc ? date.getUTCDate() : date.getDate();
    format = format.replace(/(^|[^\\])dddd+/g, "$1" + dddd[0]);
    format = format.replace(/(^|[^\\])ddd/g, "$1" + ddd[0]);
    format = format.replace(/(^|[^\\])dd/g, "$1" + ii(d));
    format = format.replace(/(^|[^\\])d/g, "$1" + d);

    var H = utc ? date.getUTCHours() : date.getHours();
    format = format.replace(/(^|[^\\])HH+/g, "$1" + ii(H));
    format = format.replace(/(^|[^\\])H/g, "$1" + H);

    var h = H > 12 ? H - 12 : H == 0 ? 12 : H;
    format = format.replace(/(^|[^\\])hh+/g, "$1" + ii(h));
    format = format.replace(/(^|[^\\])h/g, "$1" + h);

    var m = utc ? date.getUTCMinutes() : date.getMinutes();
    format = format.replace(/(^|[^\\])mm+/g, "$1" + ii(m));
    format = format.replace(/(^|[^\\])m/g, "$1" + m);

    var s = utc ? date.getUTCSeconds() : date.getSeconds();
    format = format.replace(/(^|[^\\])ss+/g, "$1" + ii(s));
    format = format.replace(/(^|[^\\])s/g, "$1" + s);

    var f = utc ? date.getUTCMilliseconds() : date.getMilliseconds();
    format = format.replace(/(^|[^\\])fff+/g, "$1" + ii(f, 3));
    f = Math.round(f / 10);
    format = format.replace(/(^|[^\\])ff/g, "$1" + ii(f));
    f = Math.round(f / 10);
    format = format.replace(/(^|[^\\])f/g, "$1" + f);

    var T = H < 12 ? "AM" : "PM";
    format = format.replace(/(^|[^\\])TT+/g, "$1" + T);
    format = format.replace(/(^|[^\\])T/g, "$1" + T.charAt(0));

    var t = T.toLowerCase();
    format = format.replace(/(^|[^\\])tt+/g, "$1" + t);
    format = format.replace(/(^|[^\\])t/g, "$1" + t.charAt(0));

    var tz = -date.getTimezoneOffset();
    var K = utc || !tz ? "Z" : tz > 0 ? "+" : "-";
    if (!utc) {
        tz = Math.abs(tz);
        var tzHrs = Math.floor(tz / 60);
        var tzMin = tz % 60;
        K += ii(tzHrs) + ":" + ii(tzMin);
    }
    format = format.replace(/(^|[^\\])K/g, "$1" + K);

    var day = (utc ? date.getUTCDay() : date.getDay()) + 1;
    format = format.replace(new RegExp(dddd[0], "g"), dddd[day]);
    format = format.replace(new RegExp(ddd[0], "g"), ddd[day]);

    format = format.replace(new RegExp(MMMM[0], "g"), MMMM[M]);
    format = format.replace(new RegExp(MMM[0], "g"), MMM[M]);

    format = format.replace(/\\(.)/g, "$1");

    return format;
};

function setCookieDays(name, value, days) {
	let expires = "";
	if (days) {
		let d = new Date();
		d.setTime(d.getTime() + (days * 24 * 60 * 60 * 1000));
		expires = "expires=" + d.toUTCString();
	}
	document.cookie = name + "=" + JSON.stringify(value) + ";" + expires + ";SameSite=Lax" + ";path=/";
}

function setCookie(name, value) {
	let expires = "";
	let d = new Date();
	d.setTime(d.getTime() + (100 * 365 * 24 * 60 * 60 * 1000));
	expires = "expires=" + d.toUTCString();
	document.cookie = name + "=" + JSON.stringify(value) + ";" + expires + ";SameSite=Lax" + ";path=/";
}

function deleteAllCookies() {
    document.cookie.split(';').forEach(cookie => {
        const eqPos = cookie.indexOf('=');
        const name = eqPos > -1 ? cookie.substring(0, eqPos) : cookie;
        document.cookie = name + '=;expires=Thu, 01 Jan 1970 00:00:00 GMT';
    });
}

function getCookie(name) {
	const nameEQ = name + "=";
	const ca = document.cookie.split(';');
	for (let i = 0; i < ca.length; i++) {
	let c = ca[i];
		while (c.charAt(0) === ' ')
			c = c.substring(1, c.length);

		if (c.indexOf(nameEQ) === 0) {
			return JSON.parse(c.substring(nameEQ.length, c.length));
		}
	}
	return null;
}

function cookieSetPhoto(file_id) {
	setCookie("photo", file_id);
}

async function telegramGetPhoto() {
	response = await fetch(`https://api.telegram.org/bot${database_bot.TOKEN}/getFile?file_id=${getCookie("photo")}`);
	json = await response.json();
	if (json.ok == false) {
		return "assets/img/user.png";
	}
	result = "https://api.telegram.org/file/bot" + database_bot.TOKEN + "/" + await json.result.file_path;
    console.log("photo_json: " + JSON.stringify(result));
    return await result;
}

async function getCookiePhoto() {
	return await telegramGetPhoto();
    //setCookie("photo", result, 0);
    
	//return "assets/img/user.png";
}

async function generateRSAKeyPair() {
                const keyPair = await window.crypto.subtle.generateKey(
                    {
                        name: "RSA-OAEP",
                        modulusLength: 2048,
                        publicExponent: new Uint8Array([1, 0, 1]),
                        hash: "SHA-256",
                    },
                    true, // whether the key is extractable (i.e. can be used in exportKey)
                    ["encrypt", "decrypt"] // can be any combination of "sign" and "verify" or "encrypt" and "decrypt"
                );

                const publicKey = await window.crypto.subtle.exportKey("spki", keyPair.publicKey);
                const privateKey = await window.crypto.subtle.exportKey("pkcs8", keyPair.privateKey);

                return {
                    publicKey: arrayBufferToBase64(publicKey),
                    privateKey: arrayBufferToBase64(privateKey),
                };
            }

            function arrayBufferToBase64(buffer) {
                const binary = String.fromCharCode(...new Uint8Array(buffer));
                return window.btoa(binary);
            }



async function generateCookies(success) {
	const charset = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';
	const numbers = '0123456789';
	const randomString = generateRandomString(32, charset);
	const randumNumbers = generateRandomString(10, numbers);

	await loadDatabase();
	setCookie("id", 1000000000 + userCount, 0);
	database.usercount++;
	console.log("user: " + JSON.stringify(database));
	saveDatabase(success);

	generateRSAKeyPair().then((keyPair) => {
		setCookie("public_key", keyPair.publicKey);
		setCookie("private_key", keyPair.privateKey);
	});

	setCookie("name", "user" + randumNumbers, 0);
	setCookie("photo", "assets/img/user.png");
	setCookie("key", randomString);
	console.log("Created new cookies.");
}

function checkCookies() {
	console.log("Check cookies...");
	console.log("Cookie ID: " + getCookie("id"));
	
	if (getCookie("id") == null || getCookie("id") == "invalid") {
		generateCookies();
	} else {
		console.log("failed create new cookies." + getCookie("id"));
	}
}