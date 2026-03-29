using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace CyberBrief.Migrations
{
    /// <inheritdoc />
    public partial class AddThreatScoreToUrlAnalysisRecord : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddColumn<int>(
                name: "GsbScore",
                table: "UrlAnalysisRecords",
                type: "int",
                nullable: false,
                defaultValue: 0);

            migrationBuilder.AddColumn<int>(
                name: "MlScore",
                table: "UrlAnalysisRecords",
                type: "int",
                nullable: false,
                defaultValue: 0);

            migrationBuilder.AddColumn<string>(
                name: "ThreatLevel",
                table: "UrlAnalysisRecords",
                type: "nvarchar(max)",
                nullable: false,
                defaultValue: "");

            migrationBuilder.AddColumn<int>(
                name: "VtScore",
                table: "UrlAnalysisRecords",
                type: "int",
                nullable: false,
                defaultValue: 0);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropColumn(
                name: "GsbScore",
                table: "UrlAnalysisRecords");

            migrationBuilder.DropColumn(
                name: "MlScore",
                table: "UrlAnalysisRecords");

            migrationBuilder.DropColumn(
                name: "ThreatLevel",
                table: "UrlAnalysisRecords");

            migrationBuilder.DropColumn(
                name: "VtScore",
                table: "UrlAnalysisRecords");
        }
    }
}
