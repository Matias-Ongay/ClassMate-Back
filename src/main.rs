use actix_web::{web, HttpResponse, Responder, App, HttpServer};
use actix_cors::Cors;
use serde::{Serialize, Deserialize};
use bcrypt::{hash, verify, DEFAULT_COST};
use rusqlite::{Connection, Result};
use std::sync::{Arc, Mutex};

// User data structure
#[derive(Debug, Serialize, Deserialize)]
struct User {
    id: i32,
    username: String,
    password_hash: String,
}

// Task data structure
#[derive(Debug, Serialize, Deserialize)]
struct Task {
    id: i32,
    title: String,
    status: String, 
    note: Option<String>,
    user_id: i32,
}

// Subject data structure
#[derive(Debug, Serialize, Deserialize)]
struct Subject {
    id: i32,
    name: String,
    user_id: i32,
}

// ExamDate data structure
#[derive(Debug, Serialize, Deserialize)]
struct ExamDate {
    id: i32,
    subject_id: i32,
    date: String,
}

// Note data structure
#[derive(Debug, Serialize, Deserialize)]
struct Note {
    id: i32,
    subject_id: i32,
    content: String,
}

// FileLink data structure
#[derive(Debug, Serialize, Deserialize)]
struct FileLink {
    id: i32,
    subject_id: i32,
    url: String,
}

// Request structures
#[derive(Debug, Deserialize)]
struct RegisterRequest {
    username: String,
    password: String,
}

#[derive(Debug, Deserialize)]
struct LoginRequest {
    username: String,
    password: String,
}

#[derive(Debug, Deserialize)]
struct AddTaskRequest {
    title: String,
    status: String,
    note: Option<String>,
    user_id: i32,
}

#[derive(Debug, Deserialize)]
struct UpdateTaskStatusRequest {
    task_id: i32,
    new_status: String,
}

#[derive(Debug, Deserialize)]
struct UpdateTaskNoteRequest {
    task_id: i32,
    new_note: String,
}

#[derive(Debug, Deserialize)]
struct AddSubjectRequest {
    name: String,
    user_id: i32,
}

#[derive(Debug, Deserialize)]
struct AddExamDateRequest {
    subject_id: i32,
    date: String,
}

#[derive(Debug, Deserialize)]
struct AddNoteRequest {
    subject_id: i32,
    content: String,
}

#[derive(Debug, Deserialize)]
struct AddFileLinkRequest {
    subject_id: i32,
    url: String,
}

// Handler functions
async fn register(
    register_info: web::Json<RegisterRequest>,
    db_conn: web::Data<Arc<Mutex<Connection>>>,
) -> impl Responder {
    let username = &register_info.username;
    let password = &register_info.password;

    let password_hash = match hash(password, DEFAULT_COST) {
        Ok(hash) => hash,
        Err(_) => return HttpResponse::InternalServerError().body("Error al hashear la contraseña"),
    };

    match insert_user(&db_conn, username, &password_hash) {
        Ok(_) => HttpResponse::Ok().body("Usuario registrado exitosamente"),
        Err(_) => HttpResponse::InternalServerError().body("Error al registrar el usuario"),
    }
}

async fn login(
    login_info: web::Json<LoginRequest>,
    db_conn: web::Data<Arc<Mutex<Connection>>>,
) -> impl Responder {
    let username = &login_info.username;
    let password = &login_info.password;

    match find_user(&db_conn, username) {
        Ok(user) => {
            if verify(password, &user.password_hash).unwrap_or(false) {
                HttpResponse::Ok().json(serde_json::json!({ "message": "Inicio de sesión exitoso", "user_id": user.id }))
            } else {
                HttpResponse::Unauthorized().body("Credenciales inválidas")
            }
        }
        Err(_) => HttpResponse::Unauthorized().body("Credenciales inválidas"),
    }
}

async fn add_task(
    add_task_info: web::Json<AddTaskRequest>,
    db_conn: web::Data<Arc<Mutex<Connection>>>,
) -> impl Responder {
    let title = &add_task_info.title;
    let status = &add_task_info.status;
    let note = add_task_info.note.as_deref();
    let user_id = add_task_info.user_id;

    match insert_task(&db_conn, title, status, note, user_id) {
        Ok(_) => HttpResponse::Ok().body("Tarea agregada exitosamente"),
        Err(_) => HttpResponse::InternalServerError().body("Error al agregar la tarea"),
    }
}

async fn delete_task(
    task_id: web::Path<i32>,
    db_conn: web::Data<Arc<Mutex<Connection>>>,
) -> impl Responder {
    let id = task_id.into_inner();

    match remove_task(&db_conn, id) {
        Ok(_) => HttpResponse::Ok().body("Tarea eliminada exitosamente"),
        Err(_) => HttpResponse::InternalServerError().body("Error al eliminar la tarea"),
    }
}

async fn update_task_status(
    update_info: web::Json<UpdateTaskStatusRequest>,
    db_conn: web::Data<Arc<Mutex<Connection>>>,
) -> impl Responder {
    let task_id = update_info.task_id;
    let new_status = &update_info.new_status;

    match new_status.as_str() {
        "Pendiente" | "En ejecucion" | "Tarea finalizada" => {
            match modify_task_status(&db_conn, task_id, new_status) {
                Ok(_) => HttpResponse::Ok().body("Estado de la tarea actualizado exitosamente"),
                Err(_) => HttpResponse::InternalServerError().body("Error al actualizar el estado de la tarea"),
            }
        }
        _ => HttpResponse::BadRequest().body("Estado de tarea no válido"),
    }
}

async fn update_task_note(
    update_info: web::Json<UpdateTaskNoteRequest>,
    db_conn: web::Data<Arc<Mutex<Connection>>>,
) -> impl Responder {
    let task_id = update_info.task_id;
    let new_note = &update_info.new_note;

    match modify_task_note(&db_conn, task_id, new_note) {
        Ok(_) => HttpResponse::Ok().body("Nota de la tarea actualizada exitosamente"),
        Err(_) => HttpResponse::InternalServerError().body("Error al actualizar la nota de la tarea"),
    }
}

async fn add_subject(
    add_subject_info: web::Json<AddSubjectRequest>,
    db_conn: web::Data<Arc<Mutex<Connection>>>,
) -> impl Responder {
    let name = &add_subject_info.name;
    let user_id = add_subject_info.user_id;

    match insert_subject(&db_conn, name, user_id) {
        Ok(_) => HttpResponse::Ok().body("Materia agregada exitosamente"),
        Err(_) => HttpResponse::InternalServerError().body("Error al agregar la materia"),
    }
}

async fn delete_subject(
    subject_id: web::Path<i32>,
    db_conn: web::Data<Arc<Mutex<Connection>>>,
) -> impl Responder {
    let id = subject_id.into_inner();

    match remove_subject(&db_conn, id) {
        Ok(_) => HttpResponse::Ok().body("Materia eliminada exitosamente"),
        Err(_) => HttpResponse::InternalServerError().body("Error al eliminar la materia"),
    }
}

async fn add_exam_date(
    add_exam_date_info: web::Json<AddExamDateRequest>,
    db_conn: web::Data<Arc<Mutex<Connection>>>,
) -> impl Responder {
    let subject_id = add_exam_date_info.subject_id;
    let date = &add_exam_date_info.date;

    match insert_exam_date(&db_conn, subject_id, date) {
        Ok(_) => HttpResponse::Ok().body("Fecha de examen agregada exitosamente"),
        Err(_) => HttpResponse::InternalServerError().body("Error al agregar la fecha de examen"),
    }
}

async fn add_note(
    add_note_info: web::Json<AddNoteRequest>,
    db_conn: web::Data<Arc<Mutex<Connection>>>,
) -> impl Responder {
    let subject_id = add_note_info.subject_id;
    let content = &add_note_info.content;

    match insert_note(&db_conn, subject_id, content) {
        Ok(_) => HttpResponse::Ok().body("Nota agregada exitosamente"),
        Err(_) => HttpResponse::InternalServerError().body("Error al agregar la nota"),
    }
}

async fn add_file_link(
    add_file_link_info: web::Json<AddFileLinkRequest>,
    db_conn: web::Data<Arc<Mutex<Connection>>>,
) -> impl Responder {
    let subject_id = add_file_link_info.subject_id;
    let url = &add_file_link_info.url;

    match insert_file_link(&db_conn, subject_id, url) {
        Ok(_) => HttpResponse::Ok().body("Enlace de archivo agregado exitosamente"),
        Err(_) => HttpResponse::InternalServerError().body("Error al agregar el enlace de archivo"),
    }
}

// Getters
async fn get_tasks(db_conn: web::Data<Arc<Mutex<Connection>>>, user_id: web::Path<i32>) -> impl Responder {
    let conn = db_conn.lock().unwrap();
    let mut stmt = conn.prepare("SELECT id, title, status, note, user_id FROM tasks WHERE user_id = ?1").unwrap();
    let task_iter = stmt.query_map(&[&user_id.into_inner()], |row| {
        Ok(Task {
            id: row.get(0)?,
            title: row.get(1)?,
            status: row.get(2)?,
            note: row.get(3)?,
            user_id: row.get(4)?,
        })
    }).unwrap();

    let tasks: Vec<Task> = task_iter.map(|task| task.unwrap()).collect();

    HttpResponse::Ok().json(tasks)
}

async fn get_subjects(
    db_conn: web::Data<Arc<Mutex<Connection>>>,
    user_id: web::Path<i32>,
) -> impl Responder {
    let conn = db_conn.lock().unwrap();
    let mut stmt = conn.prepare("SELECT id, name, user_id FROM subjects WHERE user_id = ?1").unwrap();
    let subject_iter = stmt.query_map(&[&user_id.to_string()], |row| {
        Ok(Subject {
            id: row.get(0)?,
            name: row.get(1)?,
            user_id: row.get(2)?,
        })
    }).unwrap();

    let subjects: Vec<Subject> = subject_iter.map(|subject| subject.unwrap()).collect();

    HttpResponse::Ok().json(subjects)
}

async fn get_exam_dates(
    db_conn: web::Data<Arc<Mutex<Connection>>>,
    subject_id: web::Path<i32>,
) -> impl Responder {
    let conn = db_conn.lock().unwrap();
    let mut stmt = conn.prepare("SELECT id, subject_id, date FROM exam_dates WHERE subject_id = ?1").unwrap();
    let exam_date_iter = stmt.query_map(&[&subject_id.into_inner()], |row| {
        Ok(ExamDate {
            id: row.get(0)?,
            subject_id: row.get(1)?,
            date: row.get(2)?,
        })
    }).unwrap();

    let exam_dates: Vec<ExamDate> = exam_date_iter.map(|exam_date| exam_date.unwrap()).collect();

    HttpResponse::Ok().json(exam_dates)
}

async fn get_notes(
    db_conn: web::Data<Arc<Mutex<Connection>>>,
    subject_id: web::Path<i32>,
) -> impl Responder {
    let conn = db_conn.lock().unwrap();
    let mut stmt = conn.prepare("SELECT id, subject_id, content FROM notes WHERE subject_id = ?1").unwrap();
    let note_iter = stmt.query_map(&[&subject_id.into_inner()], |row| {
        Ok(Note {
            id: row.get(0)?,
            subject_id: row.get(1)?,
            content: row.get(2)?,
        })
    }).unwrap();

    let notes: Vec<Note> = note_iter.map(|note| note.unwrap()).collect();

    HttpResponse::Ok().json(notes)
}

async fn get_file_links(
    db_conn: web::Data<Arc<Mutex<Connection>>>,
    subject_id: web::Path<i32>,
) -> impl Responder {
    let conn = db_conn.lock().unwrap();
    let mut stmt = conn.prepare("SELECT id, subject_id, url FROM file_links WHERE subject_id = ?1").unwrap();
    let file_link_iter = stmt.query_map(&[&subject_id.into_inner()], |row| {
        Ok(FileLink {
            id: row.get(0)?,
            subject_id: row.get(1)?,
            url: row.get(2)?,
        })
    }).unwrap();

    let file_links: Vec<FileLink> = file_link_iter.map(|file_link| file_link.unwrap()).collect();

    HttpResponse::Ok().json(file_links)
}
async fn delete_note(
    note_id: web::Path<i32>,
    db_conn: web::Data<Arc<Mutex<Connection>>>,
) -> impl Responder {
    let id = note_id.into_inner();

    match remove_note(&db_conn, id) {
        Ok(_) => HttpResponse::Ok().body("Nota eliminada exitosamente"),
        Err(_) => HttpResponse::InternalServerError().body("Error al eliminar la nota"),
    }
}

fn remove_note(
    db_conn: &web::Data<Arc<Mutex<Connection>>>,
    note_id: i32,
) -> Result<()> {
    let mut conn = db_conn.lock().unwrap();
    conn.execute(
        "DELETE FROM notes WHERE id = ?1",
        &[&note_id.to_string()],
    )?;
    Ok(())
}
// Database modification functions
fn insert_user(
    db_conn: &web::Data<Arc<Mutex<Connection>>>,
    username: &str,
    password_hash: &str,
) -> Result<()> {
    let mut conn = db_conn.lock().unwrap();
    conn.execute(
        "INSERT INTO users (username, password_hash) VALUES (?1, ?2)",
        &[username, password_hash],
    )?;
    Ok(())
}

fn find_user(
    db_conn: &web::Data<Arc<Mutex<Connection>>>,
    username: &str,
) -> Result<User> {
    let mut conn = db_conn.lock().unwrap();
    let mut stmt = conn.prepare(
        "SELECT id, username, password_hash FROM users WHERE username = ?1",
    )?;
    let user_row = stmt.query_row(&[username], |row| {
        Ok(User {
            id: row.get(0)?,
            username: row.get(1)?,
            password_hash: row.get(2)?,
        })
    })?;
    Ok(user_row)
}

fn insert_task(
    db_conn: &web::Data<Arc<Mutex<Connection>>>,
    title: &str,
    status: &str,
    note: Option<&str>,
    user_id: i32,
) -> Result<()> {
    let mut conn = db_conn.lock().unwrap();
    conn.execute(
        "INSERT INTO tasks (title, status, note, user_id) VALUES (?1, ?2, ?3, ?4)",
        &[title, status, &note.unwrap_or(""), &user_id.to_string()],
    )?;
    Ok(())
}

fn remove_task(
    db_conn: &web::Data<Arc<Mutex<Connection>>>,
    task_id: i32,
) -> Result<()> {
    let mut conn = db_conn.lock().unwrap();
    conn.execute(
        "DELETE FROM tasks WHERE id = ?1",
        &[&task_id.to_string()],
    )?;
    Ok(())
}

fn modify_task_status(
    db_conn: &web::Data<Arc<Mutex<Connection>>>,
    task_id: i32,
    new_status: &str,
) -> Result<()> {
    let mut conn = db_conn.lock().unwrap();
    conn.execute(
        "UPDATE tasks SET status = ?1 WHERE id = ?2",
        &[new_status, &task_id.to_string()],
    )?;
    Ok(())
}

fn modify_task_note(
    db_conn: &web::Data<Arc<Mutex<Connection>>>,
    task_id: i32,
    new_note: &str,
) -> Result<()> {
    let mut conn = db_conn.lock().unwrap();
    conn.execute(
        "UPDATE tasks SET note = ?1 WHERE id = ?2",
        &[new_note, &task_id.to_string()],
    )?;
    Ok(())
}

fn insert_subject(
    db_conn: &web::Data<Arc<Mutex<Connection>>>,
    name: &str,
    user_id: i32,
) -> Result<()> {
    let mut conn = db_conn.lock().unwrap();
    conn.execute(
        "INSERT INTO subjects (name, user_id) VALUES (?1, ?2)",
        &[name, &user_id.to_string()],
    )?;
    Ok(())
}

fn remove_subject(
    db_conn: &web::Data<Arc<Mutex<Connection>>>,
    subject_id: i32,
) -> Result<()> {
    let mut conn = db_conn.lock().unwrap();
    conn.execute(
        "DELETE FROM notes WHERE subject_id = ?1",
        &[&subject_id.to_string()],
    )?;
    conn.execute(
        "DELETE FROM exam_dates WHERE subject_id = ?1",
        &[&subject_id.to_string()],
    )?;
    conn.execute(
        "DELETE FROM file_links WHERE subject_id = ?1",
        &[&subject_id.to_string()],
    )?;
    conn.execute(
        "DELETE FROM subjects WHERE id = ?1",
        &[&subject_id.to_string()],
    )?;
    Ok(())
}


fn insert_exam_date(
    db_conn: &web::Data<Arc<Mutex<Connection>>>,
    subject_id: i32,
    date: &str,
) -> Result<()> {
    let mut conn = db_conn.lock().unwrap();
    conn.execute(
        "INSERT INTO exam_dates (subject_id, date) VALUES (?1, ?2)",
        &[&subject_id.to_string(), date],
    )?;
    Ok(())
}

fn insert_note(
    db_conn: &web::Data<Arc<Mutex<Connection>>>,
    subject_id: i32,
    content: &str,
) -> Result<()> {
    let mut conn = db_conn.lock().unwrap();
    conn.execute(
        "INSERT INTO notes (subject_id, content) VALUES (?1, ?2)",
        &[&subject_id.to_string(), content],
    )?;
    Ok(())
}

fn insert_file_link(
    db_conn: &web::Data<Arc<Mutex<Connection>>>,
    subject_id: i32,
    url: &str,
) -> Result<()> {
    let mut conn = db_conn.lock().unwrap();
    conn.execute(
        "INSERT INTO file_links (subject_id, url) VALUES (?1, ?2)",
        &[&subject_id.to_string(), url],
    )?;
    Ok(())
}

// Main function
#[actix_web::main]
async fn main() -> std::io::Result<()> {
    let db_path = "classmate.db";
    let db_conn = Arc::new(Mutex::new(Connection::open(db_path).expect("Failed to connect to database.")));

    // Create necessary tables if they don't exist
    {
        let mut conn = db_conn.lock().unwrap();
        conn.execute(
            "CREATE TABLE IF NOT EXISTS users (
                 id INTEGER PRIMARY KEY,
                 username TEXT NOT NULL UNIQUE,
                 password_hash TEXT NOT NULL
             )",
            [],
        )
        .expect("Failed to create users table.");
    }

    {
        let mut conn = db_conn.lock().unwrap();
        conn.execute(
            "ALTER TABLE tasks ADD COLUMN user_id INTEGER",
            [],
        )
        .ok(); // Ignore error if column already exists
        conn.execute(
            "CREATE TABLE IF NOT EXISTS tasks (
                 id INTEGER PRIMARY KEY,
                 title TEXT NOT NULL,
                 status TEXT NOT NULL,
                 note TEXT,
                 user_id INTEGER NOT NULL,
                 FOREIGN KEY (user_id) REFERENCES users(id)
             )",
            [],
        )
        .expect("Failed to create tasks table.");
    }

    {
        let mut conn = db_conn.lock().unwrap();
        conn.execute(
            "ALTER TABLE subjects ADD COLUMN user_id INTEGER",
            [],
        )
        .ok(); // Ignore error if column already exists
        conn.execute(
            "CREATE TABLE IF NOT EXISTS subjects (
                 id INTEGER PRIMARY KEY,
                 name TEXT NOT NULL,
                 user_id INTEGER NOT NULL,
                 FOREIGN KEY (user_id) REFERENCES users(id)
             )",
            [],
        )
        .expect("Failed to create subjects table.");
    }

    {
        let mut conn = db_conn.lock().unwrap();
        conn.execute(
            "CREATE TABLE IF NOT EXISTS exam_dates (
                 id INTEGER PRIMARY KEY,
                 subject_id INTEGER NOT NULL,
                 date TEXT NOT NULL,
                 FOREIGN KEY (subject_id) REFERENCES subjects(id)
             )",
            [],
        )
        .expect("Failed to create exam_dates table.");
    }

    {
        let mut conn = db_conn.lock().unwrap();
        conn.execute(
            "CREATE TABLE IF NOT EXISTS notes (
                 id INTEGER PRIMARY KEY,
                 subject_id INTEGER NOT NULL,
                 content TEXT NOT NULL,
                 FOREIGN KEY (subject_id) REFERENCES subjects(id)
             )",
            [],
        )
        .expect("Failed to create notes table.");
    }

    {
        let mut conn = db_conn.lock().unwrap();
        conn.execute(
            "CREATE TABLE IF NOT EXISTS file_links (
                 id INTEGER PRIMARY KEY,
                 subject_id INTEGER NOT NULL,
                 url TEXT NOT NULL,
                 FOREIGN KEY (subject_id) REFERENCES subjects(id)
             )",
            [],
        )
        .expect("Failed to create file_links table.");
    }

    // Start the server
    HttpServer::new(move || {
        let cors = Cors::default()
            .allow_any_origin()
            .allow_any_method()
            .allow_any_header()
            .max_age(3600);
    
        App::new()
            .wrap(cors)
            .app_data(web::Data::new(db_conn.clone()))
            .service(web::resource("/register").route(web::post().to(register)))
            .service(web::resource("/login").route(web::post().to(login)))
            .service(web::resource("/add_task").route(web::post().to(add_task)))
            .service(web::resource("/update_task_status").route(web::post().to(update_task_status)))
            .service(web::resource("/delete_task/{task_id}").route(web::delete().to(delete_task)))
            .service(web::resource("/get_tasks/{user_id}").route(web::get().to(get_tasks)))
            .service(web::resource("/update_task_note").route(web::post().to(update_task_note)))
            .service(web::resource("/add_subject").route(web::post().to(add_subject)))
            .service(web::resource("/delete_subject/{subject_id}").route(web::delete().to(delete_subject)))
            .service(web::resource("/get_subjects/{user_id}").route(web::get().to(get_subjects)))
            .service(web::resource("/get_exam_dates/{subject_id}").route(web::get().to(get_exam_dates)))
            .service(web::resource("/get_notes/{subject_id}").route(web::get().to(get_notes)))
            .service(web::resource("/get_file_links/{subject_id}").route(web::get().to(get_file_links)))
            .service(web::resource("/add_exam_date").route(web::post().to(add_exam_date)))
            .service(web::resource("/add_note").route(web::post().to(add_note)))
            .service(web::resource("/add_file_link").route(web::post().to(add_file_link)))
            .service(web::resource("/delete_note/{note_id}").route(web::delete().to(delete_note))) // Nueva ruta
    })
    .bind("127.0.0.1:8080")?
    .run()
    .await
    
}
