export default function LoginPage() {
  return (
    <main>
      <section className="card">
        <h1>Login de teste</h1>
        <p>Interface preparada para conectar ao Neon Auth.</p>
        <form style={{display:'grid',gap:12,textAlign:'left'}}>
          <label>E-mail<input name="email" type="email" required style={{display:'block',width:'100%',padding:12,marginTop:6}} /></label>
          <label>Senha<input name="password" type="password" required style={{display:'block',width:'100%',padding:12,marginTop:6}} /></label>
          <button type="submit" style={{padding:12}}>Entrar</button>
        </form>
      </section>
    </main>
  );
}
