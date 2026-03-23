using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace CyberBrief.Migrations
{
    /// <inheritdoc />
    public partial class FixinEmaillogic : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropForeignKey(
                name: "FK_Founds_Results_ResultId",
                table: "Founds");

            migrationBuilder.DropPrimaryKey(
                name: "PK_Founds",
                table: "Founds");

            migrationBuilder.AddColumn<string>(
                name: "Email",
                table: "Results",
                type: "nvarchar(max)",
                nullable: false,
                defaultValue: "");

            migrationBuilder.AlterColumn<string>(
                name: "ResultId",
                table: "Founds",
                type: "nvarchar(450)",
                nullable: false,
                defaultValue: "",
                oldClrType: typeof(string),
                oldType: "nvarchar(450)",
                oldNullable: true);

            migrationBuilder.AlterColumn<string>(
                name: "Email",
                table: "Founds",
                type: "nvarchar(max)",
                nullable: false,
                oldClrType: typeof(string),
                oldType: "nvarchar(450)");

            migrationBuilder.AddColumn<string>(
                name: "Id",
                table: "Founds",
                type: "nvarchar(450)",
                nullable: false,
                defaultValue: "");

            migrationBuilder.AddPrimaryKey(
                name: "PK_Founds",
                table: "Founds",
                column: "Id");

            migrationBuilder.AddForeignKey(
                name: "FK_Founds_Results_ResultId",
                table: "Founds",
                column: "ResultId",
                principalTable: "Results",
                principalColumn: "Id",
                onDelete: ReferentialAction.Cascade);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropForeignKey(
                name: "FK_Founds_Results_ResultId",
                table: "Founds");

            migrationBuilder.DropPrimaryKey(
                name: "PK_Founds",
                table: "Founds");

            migrationBuilder.DropColumn(
                name: "Email",
                table: "Results");

            migrationBuilder.DropColumn(
                name: "Id",
                table: "Founds");

            migrationBuilder.AlterColumn<string>(
                name: "ResultId",
                table: "Founds",
                type: "nvarchar(450)",
                nullable: true,
                oldClrType: typeof(string),
                oldType: "nvarchar(450)");

            migrationBuilder.AlterColumn<string>(
                name: "Email",
                table: "Founds",
                type: "nvarchar(450)",
                nullable: false,
                oldClrType: typeof(string),
                oldType: "nvarchar(max)");

            migrationBuilder.AddPrimaryKey(
                name: "PK_Founds",
                table: "Founds",
                column: "Email");

            migrationBuilder.AddForeignKey(
                name: "FK_Founds_Results_ResultId",
                table: "Founds",
                column: "ResultId",
                principalTable: "Results",
                principalColumn: "Id");
        }
    }
}
