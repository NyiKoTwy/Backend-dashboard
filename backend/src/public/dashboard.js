const BASE_URL = window.location.hostname === "localhost"
    ? "http://localhost:3000"  // Local backend
    : "https://backend-dashboard-l0ta.onrender.com";  // Deployed backend

function showLoadingSpinner(isLoading) {
    const spinner = document.getElementById("loading-spinner");
    if (spinner) {
        spinner.style.display = isLoading ? "flex" : "none"; // Show when loading, hide when done
    }
}

document.addEventListener("DOMContentLoaded", function () {
    // Check if user is authenticated before loading anything
    if (document.body.textContent.includes('"message":"Unauthorized"')) {
        console.log("Detected unauthorized JSON response - redirecting to login");
        window.location.href = "/";
        return;
    }

    fetch(`${BASE_URL}/dashboard`, {
        method: "GET",
        credentials: "include"
    })
    .then(response => {
        if (!response.ok) {
            console.error("Authentication failed with status:", response.status);
            window.location.replace("/");
            throw new Error("Authentication failed");
        }
        return response.text();
    })
    .then(html => {
        if (html) {
            console.log("Authentication successful, loading dashboard...");
            initializeDashboard();
        }
    })
    .catch(error => {
        console.error("Error during authentication check:", error);
        window.location.href = "/";
    });
});

function initializeDashboard() {
   document.querySelector("form[action='/upload']").addEventListener("submit", function (event) {
    event.preventDefault();
    showLoadingSpinner(true); 

    let formData = new FormData(this);

    fetch(`${BASE_URL}/upload`, { 
        method: "POST",
        body: formData,
        credentials: "include"
    })
    .then(response => response.json())
    .then(data => {
        if (data && data.insights) {
            fetchInsights(); 
            updateYearOptions(data.insights); // Pass the whole insights object

            let year = data.insights.date.split("-")[0];
            document.getElementById("insights-title").textContent = `Insights for ${year}`;
        }
    })
    .catch(error => console.error("Error uploading file:", error))
    .finally(() => showLoadingSpinner(false)); 
});

    document.getElementById("year").addEventListener("change", function () {
        fetchInsights(this.value);
    });
    
    // Add event listener for the insights form
    document.getElementById("insights-form").addEventListener("submit", function(event) {
        event.preventDefault(); // Prevent default form submission
        showLoadingSpinner(true);
        
        const year = document.getElementById("year").value;
        const month = document.getElementById("month").value;
        
        fetch(`${BASE_URL}/insights`, {
            method: "POST",
            headers: {
                "Content-Type": "application/json"
            },
            credentials: "include",
            body: JSON.stringify({ year, month })
        })
        .then(response => response.json())
        .then(data => {
            if (data && data.insights) {
                document.getElementById("insights-section").style.display = "block";
                document.getElementById("insights-title").textContent = `Insights for ${year}-${month}`;
                drawCharts(data.insights);
                drawGuestBirthdays(data.insights.guestBirthdays, parseInt(month));
            }
        })
        .catch(error => {
            console.error("Error fetching insights:", error);
            document.getElementById("insights-title").textContent = "Error loading insights";
        })
        .finally(() => showLoadingSpinner(false));
    });
    
    fetchInsights();
}

function fetchInsights(selectedYear = null) {
    showLoadingSpinner(true); 

    fetch(`${BASE_URL}/api/insights`, { 
        method: "GET",
        credentials: "include"
    })
    .then(response => response.json())
    .then(insights => {
        console.log("Insights received:", insights);

        if (insights.date) {
            document.getElementById("insights-section").style.display = "block";
            updateYearOptions(insights); // Pass the whole insights object

            if (!selectedYear || insights.date.includes(selectedYear)) {
                drawCharts(insights);
                drawGuestBirthdays(insights.guestBirthdays, new Date().getMonth() + 1);
            }
        }
    })
    .catch(error => console.error("Error fetching insights:", error))
    .finally(() => showLoadingSpinner(false)); 
}

function updateYearOptions(insights) {
    const yearDropdown = document.getElementById("year");
    if (!yearDropdown) {
        console.error("Year dropdown not found!");
        return;
    }

    // Clear existing options except the default "Select Year" option
    while (yearDropdown.options.length > 1) {
        yearDropdown.remove(1);
    }

    // If we have the new availableYears array from backend
    if (typeof insights === 'object' && insights.availableYears && Array.isArray(insights.availableYears)) {
        insights.availableYears.forEach(year => {
            let newOption = document.createElement("option");
            newOption.value = year;
            newOption.textContent = year;
            yearDropdown.appendChild(newOption);
        });
    } else if (typeof insights === 'string') {
        // For backward compatibility with your existing code
        const extractedYear = insights.split("-")[0]; 
        let existingOptions = Array.from(yearDropdown.options).map(opt => opt.value);

        if (!existingOptions.includes(extractedYear)) {
            let newOption = document.createElement("option");
            newOption.value = extractedYear;
            newOption.textContent = extractedYear;
            yearDropdown.appendChild(newOption);
        }
    }
}
function drawGuestBirthdays(birthdays, selectedMonth) {
    const birthdayTable = document.getElementById("birthdayTable").getElementsByTagName('tbody')[0];
    birthdayTable.innerHTML = ''; 
    
    if (!birthdays || birthdays.length === 0) {
        const row = birthdayTable.insertRow();
        const cell = row.insertCell(0);
        cell.colSpan = 2;
        cell.textContent = "No birthdays found for this month";
        return;
    }
    
    birthdays.forEach(guest => {
        const birthdayMonth = new Date(guest.birthday).getMonth() + 1;
        if (birthdayMonth == selectedMonth) {
            const row = birthdayTable.insertRow();
            const nameCell = row.insertCell(0);
            const dateCell = row.insertCell(1);
            
            nameCell.textContent = guest.name;
            dateCell.textContent = new Date(guest.birthday).toLocaleDateString();
        }
    });

    if (birthdayTable.rows.length === 0) {
        const row = birthdayTable.insertRow();
        const cell = row.insertCell(0);
        cell.colSpan = 2;
        cell.textContent = "No birthdays found for this month";
    }
}

function drawCharts(insights) {
    console.log("Drawing charts with insights:", insights);

    if (!insights || Object.keys(insights).length === 0) {
        console.error("No valid insights data available!");
        return;
    }

    const chartConfigs = [
        {
            id: "arrivalsChart",
            type: "bar",
            label: "Arrivals",
            labels: ["Total Arrivals", "Member Arrivals", "General Guest Arrivals"],
            data: [insights.totalArrivals, insights.memberArrivals, insights.generalGuestArrivals],
            backgroundColor: ["blue", "green", "orange"]
        },
        {
            id: "occupancyChart",
            type: "bar",
            label: "Occupancy & ADR",
            labels: ["Occupancy Rate (%)", "Average Daily Rate"],
            data: [insights.occupancyRate, insights.ADR],
            backgroundColor: ["purple", "teal"]
        },
        {
            id: "ageChart",
            type: "pie",
            label: "Age Group Segmentation",
            labels: ["Child", "Adult", "Senior"],
            data: [
                insights.ageGroupSegmentation?.child || 0,
                insights.ageGroupSegmentation?.adult || 0,
                insights.ageGroupSegmentation?.senior || 0
            ],
            backgroundColor: ["yellow", "blue", "red"]
        },
        {
            id: "cancellationsChart",
            type: "bar",
            label: "Cancellations",
            labels: ["Canceled Bookings", "Cancellation Percentage"],
            data: [insights.canceledBookings.count, insights.canceledBookings.percentage],
            backgroundColor: ["red", "orange"]
        },
        {
            id: "financialChart",
            type: "bar",
            label: "Financial Summary",
            labels: ["Monthly Income", "Yearly Income"],
            data: [insights.monthlyIncome, insights.yearlyIncome],
            backgroundColor: ["green", "blue"]
        }
    ];

    chartConfigs.forEach(({ id, type, label, labels, data, backgroundColor }) => {
        const canvas = document.getElementById(id);
        if (!canvas) {
            console.error(`Canvas with id '${id}' not found!`);
            return;
        }

        if (window.chartInstances && window.chartInstances[id]) {
            window.chartInstances[id].destroy();
        }

        window.chartInstances = window.chartInstances || {};
        window.chartInstances[id] = new Chart(canvas.getContext("2d"), {
            type,
            data: {
                labels,
                datasets: [{
                    label,
                    data,
                    backgroundColor
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false
            }
        });
    });
}
