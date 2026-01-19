using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace Skills.Migrations
{
    /// <inheritdoc />
    public partial class UpdateEntities : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropForeignKey(
                name: "FK_ServicePreference_AspNetUsers_UserId",
                table: "ServicePreference");

            migrationBuilder.DropPrimaryKey(
                name: "PK_ServicePreference",
                table: "ServicePreference");

            migrationBuilder.RenameTable(
                name: "ServicePreference",
                newName: "ServicePreferences");

            migrationBuilder.RenameIndex(
                name: "IX_ServicePreference_UserId",
                table: "ServicePreferences",
                newName: "IX_ServicePreferences_UserId");

            migrationBuilder.AddColumn<string>(
                name: "Email",
                table: "EmailVerificationTokens",
                type: "text",
                nullable: false,
                defaultValue: "");

            migrationBuilder.AddColumn<DateTime>(
                name: "UsedAt",
                table: "EmailVerificationTokens",
                type: "timestamp with time zone",
                nullable: true);

            migrationBuilder.AddPrimaryKey(
                name: "PK_ServicePreferences",
                table: "ServicePreferences",
                column: "Id");

            migrationBuilder.AddForeignKey(
                name: "FK_ServicePreferences_AspNetUsers_UserId",
                table: "ServicePreferences",
                column: "UserId",
                principalTable: "AspNetUsers",
                principalColumn: "Id",
                onDelete: ReferentialAction.Cascade);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropForeignKey(
                name: "FK_ServicePreferences_AspNetUsers_UserId",
                table: "ServicePreferences");

            migrationBuilder.DropPrimaryKey(
                name: "PK_ServicePreferences",
                table: "ServicePreferences");

            migrationBuilder.DropColumn(
                name: "Email",
                table: "EmailVerificationTokens");

            migrationBuilder.DropColumn(
                name: "UsedAt",
                table: "EmailVerificationTokens");

            migrationBuilder.RenameTable(
                name: "ServicePreferences",
                newName: "ServicePreference");

            migrationBuilder.RenameIndex(
                name: "IX_ServicePreferences_UserId",
                table: "ServicePreference",
                newName: "IX_ServicePreference_UserId");

            migrationBuilder.AddPrimaryKey(
                name: "PK_ServicePreference",
                table: "ServicePreference",
                column: "Id");

            migrationBuilder.AddForeignKey(
                name: "FK_ServicePreference_AspNetUsers_UserId",
                table: "ServicePreference",
                column: "UserId",
                principalTable: "AspNetUsers",
                principalColumn: "Id",
                onDelete: ReferentialAction.Cascade);
        }
    }
}
