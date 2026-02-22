import streamlit as st
import pandas as pd
import plotly.express as px
import time
import db_manager  # <--- On importe notre connecteur SQL

# --- CONFIGURATION DE LA PAGE ---
st.set_page_config(
    page_title="War Room - Network Sentinel",
    page_icon="🛡️",
    layout="wide"
)


# --- FONCTION DE CHARGEMENT (MODE SQL) ---
def load_data():
    # On récupère les 1000 derniers logs depuis la BDD
    df = db_manager.get_recent_logs(limit=1000)

    if df.empty:
        # Structure vide si pas encore de données
        return pd.DataFrame(columns=["timestamp", "src_ip", "dst_ip", "protocol", "length", "danger_score"])

    # Conversion importante : String SQL -> DateTime Python
    df['timestamp'] = pd.to_datetime(df['timestamp'])
    return df


# --- INTERFACE ---
st.title("🛡️ NETWORK SENTINEL - WAR ROOM (SQL EDITION)")

# Placeholder pour le rafraîchissement auto
placeholder = st.empty()

while True:
    df = load_data()

    with placeholder.container():
        # KPIs
        kpi1, kpi2, kpi3 = st.columns(3)
        kpi1.metric(label="Paquets Analysés (BDD)", value=len(df))

        # Max Danger
        max_danger = df['danger_score'].max() if not df.empty else 0
        kpi2.metric(label="Niveau de Menace Max", value=f"{max_danger:.4f}")

        # Dernier protocole
        last_proto = df.iloc[0]['protocol'] if not df.empty else "N/A"
        kpi3.metric(label="Dernier Protocole", value=last_proto)

        # ALERTES VISUELLES
        if max_danger > 0.5:
            st.error(f"🚨 MENACE DÉTECTÉE ! Score: {max_danger}")
        else:
            st.success("✅ Réseau sous contrôle")

        # GRAPHIQUES
        col1, col2 = st.columns(2)

        with col1:
            st.markdown("### 📈 Trafic en Temps Réel")
            if not df.empty:
                fig = px.line(df, x="timestamp", y="danger_score", title="Score de Dangerosité")
                st.plotly_chart(fig, use_container_width=True, key=f"line_{time.time()}")

        with col2:
            st.markdown("### 🥧 Répartition des Protocoles")
            if not df.empty:
                fig_pie = px.pie(df, names='protocol', title='Protocoles Détectés')
                st.plotly_chart(fig_pie, use_container_width=True, key=f"pie_{time.time()}")

        # TABLEAU DE DONNÉES
        st.markdown("### 📋 Logs Détaillés (SQL Live)")
        st.dataframe(df.head(10))

    # Pause de 2 secondes avant le rafraîchissement
    time.sleep(2)

