const ctx1 = document.getElementById(
    "severityChart"
);


if(ctx1){

new Chart(ctx1, {

type:"doughnut",

data:{


labels:[
"Critical",
"High",
"Medium",
"Low"
],


datasets:[{

data:[
25,
40,
20,
15
],


borderWidth:0


}]


},


options:{


plugins:{


legend:{


position:"bottom",


labels:{


color:"#94a3b8"


}


}


}


}


});


}





const ctx2=document.getElementById(
"timelineChart"
);



if(ctx2){


new Chart(ctx2, {


type:"line",


data:{


labels:[

"09:00",
"10:00",
"11:00",
"12:00",
"13:00"

],


datasets:[{

label:"Threat Events",


data:[

5,
12,
8,
25,
18

],


tension:.4


}]


},


options:{


plugins:{


legend:{


labels:{


color:"#94a3b8"


}


}


},


scales:{


x:{


ticks:{


color:"#94a3b8"


}


},


y:{


ticks:{


color:"#94a3b8"


}


}


}


}


});


}