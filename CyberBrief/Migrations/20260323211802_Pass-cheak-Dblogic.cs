using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace CyberBrief.Migrations
{
    /// <inheritdoc />
    public partial class PasscheakDblogic : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.CreateTable(
                name: "PasswordAudits",
                columns: table => new
                {
                    PasswordHash = table.Column<string>(type: "nvarchar(450)", nullable: false),
                    PwnedCount = table.Column<int>(type: "int", nullable: false),
                    Entropy = table.Column<double>(type: "float", nullable: false),
                    Score = table.Column<int>(type: "int", nullable: false),
                    CrackTimeDisplay = table.Column<string>(type: "nvarchar(max)", nullable: false),
                    CheckedAt = table.Column<DateTime>(type: "datetime2", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_PasswordAudits", x => x.PasswordHash);
                });
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(
                name: "PasswordAudits");
        }
    }
}
