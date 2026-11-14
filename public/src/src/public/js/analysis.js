async function analyzeLink() {
  const link = document.getElementById('url-input').value;
  const response = await fetch(`/api/link-info?link=${encodeURIComponent(link)}`);
  const data = await response.json();
  
  displayResults(data);
}