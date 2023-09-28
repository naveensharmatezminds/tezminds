
let isCalculated = false;

function clearScreen() {
    document.getElementById("display").value = "";
}


function display(val) {
    let button = document.getElementById("display").value
    if(isCalculated){
        if(button == "+" || button == "-" || button == "/" || button == "*"){
            document.getElementById("display").value += val;
            isCalculated = false;
        }else{
            document.getElementById("display").value = "";
            document.getElementById("display").value += val;
            isCalculated = false;
        }
    }else{
        document.getElementById("display").value += val;
    }

    // document.getElementById("display").value += val;
    // console.log(val);
}
 

function cal() {
    var p = document.getElementById("display").value;
    var q = eval(p);
    isCalculated = true;
    document.getElementById("display").value = q;
}