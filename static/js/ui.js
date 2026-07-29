document.addEventListener("DOMContentLoaded", () => {


    const toggleButton = document.getElementById(
        "sidebarToggle"
    );


    const app = document.querySelector(
        ".app"
    );


    if (!toggleButton) {

        console.log("Toggle button not found");

        return;

    }


    toggleButton.addEventListener(
        "click",
        () => {


            app.classList.toggle(
                "sidebar-collapsed"
            );


            console.log(
                "Sidebar toggled"
            );


        }
    );


});