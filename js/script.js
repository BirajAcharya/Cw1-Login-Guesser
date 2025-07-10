
let menu = document.querySelector('#menu-btn');
let navbar = document.querySelector('.navbar');

menu.onclick = () => {
    menu.classList.toggle('fa-times');
    navbar.classList.toggle('active');
};

window.onscroll = () => {
    menu.classList.remove('fa-times');
    navbar.classList.remove('active');
};


function form_validate() {
    var name =
        document.forms.contactform.name.value;
    var phone =
        document.forms.contactform.phone.value;
    var RegPhone = /^\d{10}$/;									 // Javascript reGex for Phone Number validation.
    var RegName = /\d+$/g;								 // Javascript reGex for Name validation

    if (name == "" || RegName.test(name)) {
        window.alert("Please enter your name properly.");
        name.focus();
        return false;
    }

    if (phone == "" || !RegPhone.test(phone)) {
        alert("Please enter a valid 10-digit phone number.");
        phone.focus();
        return false;
    }

    alert("Form Submitted successfully!!")
    return true;
}



var swiper = new Swiper(".team-slider", {
    spaceBetween: 20,
    pagination: {
        el: ".swiper-pagination",
        clickable: true,
    },
    loop: true,
    grabCursor: true,
    autoplay: {
        delay: 7500,
        disableOnInteraction: false,
    },
    breakpoints: {
        0: {
            slidesPerView: 1
        },
        768: {
            slidesPerView: 2
        }
    },
});



  