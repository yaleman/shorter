use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        // Create users table
        manager
            .create_table(
                Table::create()
                    .table(Users::Table)
                    .if_not_exists()
                    .col(
                        ColumnDef::new(Users::Id)
                            .big_integer()
                            .not_null()
                            .auto_increment()
                            .primary_key(),
                    )
                    .col(
                        ColumnDef::new(Users::Subject)
                            .string()
                            .not_null()
                            .unique_key(),
                    )
                    .col(
                        ColumnDef::new(Users::Email)
                            .string()
                            .not_null()
                            .unique_key(),
                    )
                    .col(ColumnDef::new(Users::DisplayName).string())
                    .col(
                        ColumnDef::new(Users::CreatedAt)
                            .timestamp()
                            .not_null()
                            .default(Expr::current_timestamp()),
                    )
                    .col(
                        ColumnDef::new(Users::UpdatedAt)
                            .timestamp()
                            .not_null()
                            .default(Expr::current_timestamp()),
                    )
                    .to_owned(),
            )
            .await?;

        // Create links table
        manager
            .create_table(
                Table::create()
                    .table(Links::Table)
                    .if_not_exists()
                    .col(ColumnDef::new(Links::Id).string().not_null().primary_key())
                    .col(ColumnDef::new(Links::OwnerSubject).string().not_null())
                    .col(ColumnDef::new(Links::Name).string().not_null())
                    .col(ColumnDef::new(Links::Target).string().not_null())
                    .col(ColumnDef::new(Links::Tag).string().not_null().unique_key())
                    .col(
                        ColumnDef::new(Links::CreatedAt)
                            .timestamp()
                            .not_null()
                            .default(Expr::current_timestamp()),
                    )
                    .col(
                        ColumnDef::new(Links::UpdatedAt)
                            .timestamp()
                            .not_null()
                            .default(Expr::current_timestamp()),
                    )
                    .foreign_key(
                        ForeignKey::create()
                            .name("fk-link-owner")
                            .from(Links::Table, Links::OwnerSubject)
                            .to(Users::Table, Users::Subject)
                            .on_delete(ForeignKeyAction::Cascade)
                            .on_update(ForeignKeyAction::Cascade),
                    )
                    .to_owned(),
            )
            .await?;

        // Create index on links.owner_subject
        manager
            .create_index(
                Index::create()
                    .if_not_exists()
                    .name("idx-link-owner-subject")
                    .table(Links::Table)
                    .col(Links::OwnerSubject)
                    .to_owned(),
            )
            .await?;

        // Create pkce_states table
        manager
            .create_table(
                Table::create()
                    .table(PkceStates::Table)
                    .if_not_exists()
                    .col(
                        ColumnDef::new(PkceStates::State)
                            .string()
                            .not_null()
                            .primary_key(),
                    )
                    .col(ColumnDef::new(PkceStates::CodeVerifier).string().not_null())
                    .col(ColumnDef::new(PkceStates::Nonce).string().not_null())
                    .col(
                        ColumnDef::new(PkceStates::CodeChallenge)
                            .string()
                            .not_null(),
                    )
                    .col(ColumnDef::new(PkceStates::RedirectUri).string().not_null())
                    .col(ColumnDef::new(PkceStates::ExpiresAt).timestamp().not_null())
                    .col(
                        ColumnDef::new(PkceStates::CreatedAt)
                            .timestamp()
                            .not_null()
                            .default(Expr::current_timestamp()),
                    )
                    .to_owned(),
            )
            .await?;

        // Create index on pkce_states.expires_at for cleanup
        manager
            .create_index(
                Index::create()
                    .if_not_exists()
                    .name("idx-pkce-state-expires-at")
                    .table(PkceStates::Table)
                    .col(PkceStates::ExpiresAt)
                    .to_owned(),
            )
            .await?;

        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .drop_table(Table::drop().table(Links::Table).to_owned())
            .await?;

        manager
            .drop_table(Table::drop().table(PkceStates::Table).to_owned())
            .await?;

        manager
            .drop_table(Table::drop().table(Users::Table).to_owned())
            .await?;

        Ok(())
    }
}

#[derive(DeriveIden)]
enum Users {
    Table,
    Id,
    Subject,
    Email,
    DisplayName,
    CreatedAt,
    UpdatedAt,
}

#[derive(DeriveIden)]
enum Links {
    Table,
    Id,
    OwnerSubject,
    Name,
    Target,
    Tag,
    CreatedAt,
    UpdatedAt,
}

#[derive(DeriveIden)]
enum PkceStates {
    Table,
    State,
    CodeVerifier,
    Nonce,
    CodeChallenge,
    RedirectUri,
    ExpiresAt,
    CreatedAt,
}
