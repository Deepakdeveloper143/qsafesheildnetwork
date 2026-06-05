import plotly.graph_objects as go
import plotly.express as px

def create_risk_gauge(score: int):
    """Creates a Plotly gauge chart for risk score."""
    
    # Determine color based on score
    if score < 30:
        color = "#10b981" # Green
    elif score < 70:
        color = "#f59e0b" # Yellow
    else:
        color = "#ef4444" # Red
        
    fig = go.Figure(go.Indicator(
        mode = "gauge+number",
        value = score,
        domain = {'x': [0, 1], 'y': [0, 1]},
        title = {'text': "Risk Score"},
        gauge = {
            'axis': {'range': [None, 100], 'tickwidth': 1, 'tickcolor': "darkblue"},
            'bar': {'color': color},
            'bgcolor': "rgba(0,0,0,0)",
            'borderwidth': 2,
            'bordercolor': "gray",
            'steps': [
                {'range': [0, 30], 'color': "rgba(16, 185, 129, 0.2)"},
                {'range': [30, 70], 'color': "rgba(245, 158, 11, 0.2)"},
                {'range': [70, 100], 'color': "rgba(239, 68, 68, 0.2)"}
            ],
            'threshold': {
                'line': {'color': "red", 'width': 4},
                'thickness': 0.75,
                'value': 90
            }
        }
    ))
    
    fig.update_layout(
        paper_bgcolor="rgba(0,0,0,0)",
        font={'color': "#e2e8f0"}
    )
    
    return fig

def create_owasp_bar_chart(compliance_data: dict):
    """Creates a bar chart for OWASP compliance."""
    categories = list(compliance_data.keys())
    values = [1 if item["passed"] else 0 for item in compliance_data.values()]
    colors = ["#10b981" if v == 1 else "#ef4444" for v in values]
    
    fig = go.Figure(data=[go.Bar(
        x=categories,
        y=values,
        marker_color=colors
    )])
    
    fig.update_layout(
        title="OWASP LLM Top 10 Compliance",
        paper_bgcolor="rgba(0,0,0,0)",
        plot_bgcolor="rgba(0,0,0,0)",
        font={'color': "#e2e8f0"},
        yaxis=dict(tickvals=[0, 1], ticktext=["Failed", "Passed"])
    )
    
    return fig
