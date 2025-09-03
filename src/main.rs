use keyring::Entry;

fn main() -> keyring::Result<()> {
    let entry = Entry::new("my-service", "my-name")?;

    entry.set_password("password-here")?;

    let pwd = entry.get_password()?;

    println!("Password is {pwd}");

    entry.delete_credential()?;

    Ok(())
}
