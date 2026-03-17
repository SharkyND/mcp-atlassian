"""Attachment operations for Jira API."""

import base64
import io
import logging
import os
from pathlib import Path
from typing import Any
from urllib.parse import quote

from ..models.jira import JiraAttachment
from .attachment_cache import get_attachment_cache
from .client import JiraClient
from .protocols import AttachmentsOperationsProto

# Configure logging
logger = logging.getLogger("mcp-jira")


class AttachmentsMixin(JiraClient, AttachmentsOperationsProto):
    """Mixin for Jira attachment operations."""

    def download_attachment(self, url: str, target_path: str) -> bool:
        """
        Download a Jira attachment to the specified path.

        Args:
            url: The URL of the attachment to download
            target_path: The path where the attachment should be saved

        Returns:
            True if successful, False otherwise
        """
        if not url:
            logger.error("No URL provided for attachment download")
            return False

        try:
            # Convert to absolute path if relative
            if not os.path.isabs(target_path):
                target_path = os.path.abspath(target_path)

            logger.info(f"Downloading attachment from {url} to {target_path}")

            # Create the directory if it doesn't exist
            os.makedirs(os.path.dirname(target_path), exist_ok=True)

            # Use the Jira session to download the file
            response = self.jira._session.get(url, stream=True)
            response.raise_for_status()

            # Write the file to disk
            with open(target_path, "wb") as f:
                for chunk in response.iter_content(chunk_size=8192):
                    f.write(chunk)

            # Verify the file was created
            if os.path.exists(target_path):
                file_size = os.path.getsize(target_path)
                logger.info(
                    f"Successfully downloaded attachment to {target_path} (size: {file_size} bytes)"
                )
                return True
            else:
                logger.error(f"File was not created at {target_path}")
                return False

        except Exception as e:
            logger.error(f"Error downloading attachment: {str(e)}")
            return False

    def download_issue_attachments(
        self, issue_key: str, target_dir: str = "", return_content: bool = True
    ) -> dict[str, Any]:
        """
        Download all attachments for a Jira issue.

        Args:
            issue_key: The Jira issue key (e.g., 'PROJ-123')
            target_dir: The directory where attachments should be saved (optional)
            return_content: If True, returns MCP resource URIs instead of base64 content (default: True)

        Returns:
            A dictionary with download results, including resource URIs if requested
        """
        # Handle target directory if saving files
        target_path = None
        if target_dir:
            # Convert to absolute path if relative
            if not os.path.isabs(target_dir):
                target_dir = os.path.abspath(target_dir)

            logger.info(
                f"Downloading attachments for {issue_key} to directory: {target_dir}"
            )

            # Create the target directory if it doesn't exist
            target_path = Path(target_dir)
            target_path.mkdir(parents=True, exist_ok=True)
        else:
            logger.info(f"Fetching attachments for {issue_key} (content only)")

        # Get the issue with attachments
        logger.info(f"Fetching issue {issue_key} with attachments")
        issue_data = self.jira.issue(issue_key, fields="attachment")

        if not isinstance(issue_data, dict):
            msg = f"Unexpected return value type from `jira.issue`: {type(issue_data)}"
            logger.error(msg)
            raise TypeError(msg)

        if "fields" not in issue_data:
            logger.error(f"Could not retrieve issue {issue_key}")
            return {"success": False, "error": f"Could not retrieve issue {issue_key}"}

        # Process attachments
        attachments = []

        # Extract attachments from the API response
        attachment_data = issue_data.get("fields", {}).get("attachment", [])

        if not attachment_data:
            return {
                "success": True,
                "message": f"No attachments found for issue {issue_key}",
                "downloaded": [],
                "failed": [],
            }

        # Create JiraAttachment objects for each attachment
        for attachment in attachment_data:
            if isinstance(attachment, dict):
                attachments.append(JiraAttachment.from_api_response(attachment))

        # Download each attachment
        downloaded = []
        failed = []
        cache = get_attachment_cache()

        for attachment in attachments:
            if not attachment.url:
                logger.warning(f"No URL for attachment {attachment.filename}")
                failed.append(
                    {"filename": attachment.filename, "error": "No URL available"}
                )
                continue

            try:
                # Fetch the attachment content
                response = self.jira._session.get(attachment.url, stream=True)
                response.raise_for_status()
                content_bytes = response.content

                # Create a safe filename
                safe_filename = Path(attachment.filename).name
                
                attachment_info = {
                    "filename": attachment.filename,
                    "size": attachment.size,
                }

                # Store in cache and return resource URI if requested
                if return_content:
                    try:
                        # Determine MIME type from attachment or use generic binary
                        mime_type = attachment.content_type or "application/octet-stream"
                        
                        # Store in cache
                        cache_key = cache.store(
                            issue_key=issue_key,
                            filename=attachment.filename,
                            content=content_bytes,
                            mime_type=mime_type,
                        )
                        
                        # Static resource URI: issue_key + filename, no cache key needed.
                        # Becomes immediately accessible in MCP resource browser.
                        static_resource_uri = (
                            f"jira://attachments/{issue_key}"
                            f"/{quote(attachment.filename, safe='')}"
                        )
                        # Legacy cache-key URI (kept for backward compatibility)
                        resource_uri = (
                            f"jira://attachment/{cache_key}"
                            f"/{quote(attachment.filename, safe='')}"
                        )
                        attachment_info["static_resource_uri"] = static_resource_uri
                        attachment_info["resource_uri"] = resource_uri
                        attachment_info["cache_key"] = cache_key
                        attachment_info["mime_type"] = mime_type
                        
                        logger.info(
                            f"Cached attachment {attachment.filename} with resource URI: {resource_uri}"
                        )
                    except Exception as cache_error:
                        logger.warning(
                            f"Failed to cache {attachment.filename}: {str(cache_error)}. "
                            "Falling back to base64 encoding."
                        )
                        # Fallback to base64 if cache fails
                        content_b64 = base64.b64encode(content_bytes).decode('utf-8')
                        attachment_info["content"] = content_b64
                        attachment_info["encoding"] = "base64"

                # Save to disk if target_dir provided
                if target_path:
                    file_path = target_path / safe_filename
                    with open(file_path, "wb") as f:
                        f.write(content_bytes)
                    attachment_info["path"] = str(file_path)
                    logger.info(f"Saved attachment to {file_path}")

                downloaded.append(attachment_info)

            except Exception as e:
                logger.error(f"Failed to download {attachment.filename}: {str(e)}")
                failed.append(
                    {"filename": attachment.filename, "error": str(e)}
                )

        return {
            "success": True,
            "issue_key": issue_key,
            "total": len(attachments),
            "downloaded": downloaded,
            "failed": failed,
        }

    def upload_attachment(self, issue_key: str, file_path: str) -> dict[str, Any]:
        """
        Upload a single attachment to a Jira issue.

        Args:
            issue_key: The Jira issue key (e.g., 'PROJ-123')
            file_path: The path to the file to upload

        Returns:
            A dictionary with upload result information
        """
        if not issue_key:
            logger.error("No issue key provided for attachment upload")
            return {"success": False, "error": "No issue key provided"}

        if not file_path:
            logger.error("No file path provided for attachment upload")
            return {"success": False, "error": "No file path provided"}

        try:
            # Convert to absolute path if relative
            if not os.path.isabs(file_path):
                file_path = os.path.abspath(file_path)

            # Check if file exists
            if not os.path.exists(file_path):
                logger.error(f"File not found: {file_path}")
                return {"success": False, "error": f"File not found: {file_path}"}

            logger.info(f"Uploading attachment from {file_path} to issue {issue_key}")

            # Use the Jira API to upload the file
            filename = os.path.basename(file_path)
            with open(file_path, "rb"):
                attachment = self.jira.add_attachment(
                    issue_key=issue_key, filename=file_path
                )

            if attachment:
                file_size = os.path.getsize(file_path)
                logger.info(
                    f"Successfully uploaded attachment {filename} to {issue_key} (size: {file_size} bytes)"
                )
                return {
                    "success": True,
                    "issue_key": issue_key,
                    "filename": filename,
                    "size": file_size,
                    "id": attachment.get("id")
                    if isinstance(attachment, dict)
                    else None,
                }
            else:
                logger.error(f"Failed to upload attachment {filename} to {issue_key}")
                return {
                    "success": False,
                    "error": f"Failed to upload attachment {filename} to {issue_key}",
                }

        except Exception as e:
            error_msg = str(e)
            logger.error(f"Error uploading attachment: {error_msg}")
            return {"success": False, "error": error_msg}

    def upload_attachment_from_bytes(
        self,
        issue_key: str,
        filename: str,
        content: bytes,
        mime_type: str = "application/octet-stream",
    ) -> dict[str, Any]:
        """Upload attachment content directly from bytes to a Jira issue.

        Used by the jira_upload_attachment MCP tool, which receives file content
        from the staging store after the client POSTed files to /upload.

        Args:
            issue_key: The Jira issue key (e.g., 'PROJ-123').
            filename: Display name for the attachment in Jira.
            content: Raw file bytes.
            mime_type: MIME type (used as the content-type in the multipart upload).

        Returns:
            A dictionary with upload result information.
        """
        if not issue_key:
            return {"success": False, "error": "No issue key provided"}
        if not filename:
            return {"success": False, "error": "No filename provided"}
        if not content:
            return {"success": False, "error": "Empty file content"}

        try:
            logger.info(
                "Uploading %d bytes as '%s' to issue %s",
                len(content),
                filename,
                issue_key,
            )
            buf = io.BytesIO(content)
            # Setting .name on the BytesIO causes requests to use it as the
            # filename in the multipart form upload.
            buf.name = filename
            attachment = self.jira.add_attachment_object(issue_key, buf)
            if attachment:
                logger.info(
                    "Successfully uploaded '%s' to %s (%d bytes)",
                    filename,
                    issue_key,
                    len(content),
                )
                return {
                    "success": True,
                    "issue_key": issue_key,
                    "filename": filename,
                    "size": len(content),
                    "id": attachment.get("id") if isinstance(attachment, dict) else None,
                }
            logger.error("Upload returned empty response for '%s'", filename)
            return {
                "success": False,
                "error": f"Upload returned empty response for '{filename}'",
            }
        except Exception as e:
            error_msg = str(e)
            logger.error("Error uploading '%s': %s", filename, error_msg)
            return {"success": False, "error": error_msg}

    def upload_attachments(
        self, issue_key: str, file_paths: list[str]
    ) -> dict[str, Any]:
        """
        Upload multiple attachments to a Jira issue.

        Args:
            issue_key: The Jira issue key (e.g., 'PROJ-123')
            file_paths: List of paths to files to upload

        Returns:
            A dictionary with upload results
        """
        if not issue_key:
            logger.error("No issue key provided for attachment upload")
            return {"success": False, "error": "No issue key provided"}

        if not file_paths:
            logger.error("No file paths provided for attachment upload")
            return {"success": False, "error": "No file paths provided"}

        logger.info(f"Uploading {len(file_paths)} attachments to issue {issue_key}")

        # Upload each attachment
        uploaded = []
        failed = []

        for file_path in file_paths:
            result = self.upload_attachment(issue_key, file_path)

            if result.get("success"):
                uploaded.append(
                    {
                        "filename": result.get("filename"),
                        "size": result.get("size"),
                        "id": result.get("id"),
                    }
                )
            else:
                failed.append(
                    {
                        "filename": os.path.basename(file_path),
                        "error": result.get("error"),
                    }
                )

        return {
            "success": True,
            "issue_key": issue_key,
            "total": len(file_paths),
            "uploaded": uploaded,
            "failed": failed,
        }
