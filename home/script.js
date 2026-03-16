function verify(){
const input=document.querySelector("input").value;

if(!input.includes("@")){
alert("Please enter a valid email");
return;
}

alert("Verifying: "+input);
}