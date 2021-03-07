/// for registration page

function validateForm(){
	var name = document.forms["myForm"]["usename"].value;
	var email = document.forms["myForm"]["email"].value;
	var password = document.forms["myForm"]["password"].value;
	var password_conf = document.forms["myForm"]["confirmation"].value;

	if (name.length<1) {
        document.getElementById('error-name').innerHTML = " Please Enter Your Name *"
    }

    if (email.length<1) {
        document.getElementById('error-email').innerHTML = " Please Enter Your Email *";
    }

    if (password.length<8){
        document.getELementById('error-password').innerHTML = " Password should be at least 8 characters *"
    }

    if (password != password_conf){
        document.getELementById('error-confirmation').innerHTML = " Password does not match *"
    }

    ///prevent form to be submitted
    if(name.length<1 || email.length<1 || password != password_conf){
       	return false;
    }
}