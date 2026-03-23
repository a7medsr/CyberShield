using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace CyberBrief.Migrations
{
    /// <inheritdoc />
    public partial class changeRawjson : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropColumn(
                name: "FullReportJson",
                table: "TriageCaches");

            migrationBuilder.AddColumn<string>(
                name: "RawJson",
                table: "TriageCaches",
                type: "nvarchar(max)",
                nullable: true);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropColumn(
                name: "RawJson",
                table: "TriageCaches");

            migrationBuilder.AddColumn<string>(
                name: "FullReportJson",
                table: "TriageCaches",
                type: "nvarchar(max)",
                nullable: false,
                defaultValue: "");
        }
    }
}
