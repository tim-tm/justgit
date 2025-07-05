async function getStatus() {
    try {
        const response = await fetch("http://localhost:8080");
        if (!response.ok) throw new Error(`Response status: ${response.status}`);

        const json = await response.json();
        console.log(`Server status: ${json.status}`);
    } catch (error) {
        console.error(error.message);
    }
}
getStatus()
